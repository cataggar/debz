import { randomUUID } from 'node:crypto';
import type { Stats } from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { inflateRawSync } from 'node:zlib';

import { SetupError, errorMessage } from './errors.js';
import { sha256Bytes } from './hash.js';

export const CACHED_ARCHIVE_NAME = '.debz-release.tar.gz';
const TAR_BLOCK_SIZE = 512;
const MAX_TAR_BYTES = 64 * 1024 * 1024;
const MAX_FILE_BYTES = 32 * 1024 * 1024;
const MAX_ENTRIES = 512;

export interface ArchiveEntry {
  relativePath: string;
  type: 'directory' | 'file';
  mode: 0o644 | 0o755;
  data?: Buffer;
}

export interface ArchiveManifest {
  entries: ArchiveEntry[];
  binary: Buffer;
  binaryDigest: string;
}

function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function decodeString(field: Buffer, label: string): string {
  const terminator = field.indexOf(0);
  const end = terminator === -1 ? field.length : terminator;
  if (terminator !== -1 && field.subarray(terminator).some((byte) => byte !== 0)) {
    throw new SetupError(`${label} has nonzero bytes after its terminator`);
  }
  const value = field.subarray(0, end);
  if (value.some((byte) => byte < 0x20 || byte > 0x7e)) {
    throw new SetupError(`${label} is not printable ASCII`);
  }
  return value.toString('ascii');
}

function parseOctal(field: Buffer, label: string): number {
  if ((field[0] ?? 0) & 0x80) {
    throw new SetupError(`${label} uses unsupported base-256 encoding`);
  }
  const text = field.toString('ascii').replace(/[\0 ]+$/u, '').replace(/^ +/u, '');
  if (!/^[0-7]+$/.test(text)) {
    throw new SetupError(`${label} is not canonical octal`);
  }
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value)) {
    throw new SetupError(`${label} exceeds the supported integer range`);
  }
  return value;
}

function validateChecksum(header: Buffer): void {
  const expected = parseOctal(header.subarray(148, 156), 'tar header checksum');
  let actual = 0;
  for (let index = 0; index < header.length; index += 1) {
    actual += index >= 148 && index < 156 ? 0x20 : header[index] ?? 0;
  }
  if (actual !== expected) {
    throw new SetupError(`tar header checksum mismatch: expected ${expected}, calculated ${actual}`);
  }
}

function safeArchivePath(rawName: string, expectedRoot: string): {
  normalized: string;
  relative: string;
} {
  if (
    rawName.length === 0 ||
    rawName.startsWith('/') ||
    rawName.includes('\\') ||
    rawName.includes('\0')
  ) {
    throw new SetupError(`unsafe archive path ${JSON.stringify(rawName)}`);
  }
  const normalized = rawName.endsWith('/') ? rawName.slice(0, -1) : rawName;
  const parts = normalized.split('/');
  if (
    normalized.length === 0 ||
    parts.some((part) => part.length === 0 || part === '.' || part === '..')
  ) {
    throw new SetupError(`unsafe archive path ${JSON.stringify(rawName)}`);
  }
  if (normalized !== expectedRoot && !normalized.startsWith(`${expectedRoot}/`)) {
    throw new SetupError(`archive entry escapes expected top-level directory ${expectedRoot}`);
  }
  const relative = normalized === expectedRoot ? '' : normalized.slice(expectedRoot.length + 1);
  if (relative.length > 0) {
    const first = relative.split('/', 1)[0];
    if (!['bin', 'lib', 'share'].includes(first)) {
      throw new SetupError(`archive entry uses unexpected install path ${relative}`);
    }
  }
  return { normalized, relative };
}

export function decompressGzip(archive: Buffer): Buffer {
  if (archive.length < 18 || !archive.subarray(0, 3).equals(Buffer.from([0x1f, 0x8b, 0x08]))) {
    throw new SetupError('release archive is not a valid gzip stream');
  }
  if (archive[3] !== 0) {
    throw new SetupError('release archive gzip header contains unsupported optional fields');
  }
  if (archive.readUInt32LE(4) !== 0) {
    throw new SetupError('release archive gzip timestamp is not canonical');
  }
  const compressed = archive.subarray(10, archive.length - 8);
  let result: { buffer: Buffer; engine: { bytesWritten: number } };
  try {
    result = inflateRawSync(compressed, {
      info: true,
      maxOutputLength: MAX_TAR_BYTES,
    }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  } catch (error) {
    throw new SetupError(`release archive gzip payload is invalid: ${errorMessage(error)}`, {
      cause: error,
    });
  }
  const output = result.buffer;
  if (result.engine.bytesWritten !== compressed.length) {
    throw new SetupError('release archive gzip stream contains trailing or concatenated data');
  }
  const expectedCRC = archive.readUInt32LE(archive.length - 8);
  const expectedSize = archive.readUInt32LE(archive.length - 4);
  if (crc32(output) !== expectedCRC) {
    throw new SetupError('release archive gzip CRC-32 does not match');
  }
  if (output.length % 0x1_0000_0000 !== expectedSize) {
    throw new SetupError('release archive gzip uncompressed size does not match');
  }
  return output;
}

export function parseArchive(archive: Buffer, expectedRoot: string): ArchiveManifest {
  const tar = decompressGzip(archive);
  if (tar.length === 0 || tar.length % TAR_BLOCK_SIZE !== 0) {
    throw new SetupError('release tar stream is empty or not block-aligned');
  }

  const entries: ArchiveEntry[] = [];
  const seen = new Set<string>();
  let offset = 0;
  let zeroBlocks = 0;
  let binary: Buffer | undefined;

  while (offset < tar.length) {
    const header = tar.subarray(offset, offset + TAR_BLOCK_SIZE);
    if (header.every((byte) => byte === 0)) {
      zeroBlocks += 1;
      offset += TAR_BLOCK_SIZE;
      if (zeroBlocks >= 2) {
        if (!tar.subarray(offset).every((byte) => byte === 0)) {
          throw new SetupError('release tar stream contains data after its end marker');
        }
        break;
      }
      continue;
    }
    if (zeroBlocks > 0) {
      throw new SetupError('release tar stream contains an incomplete end marker');
    }
    if (entries.length >= MAX_ENTRIES) {
      throw new SetupError(`release tar stream exceeds ${MAX_ENTRIES} entries`);
    }
    validateChecksum(header);
    const magic = header.subarray(257, 263).toString('ascii');
    if (magic !== 'ustar\0' && magic !== 'ustar ') {
      throw new SetupError('release tar entry is not in ustar/GNU tar format');
    }
    const name = decodeString(header.subarray(0, 100), 'tar entry name');
    const prefix = decodeString(header.subarray(345, 500), 'tar entry prefix');
    const rawName = prefix ? `${prefix}/${name}` : name;
    const { normalized, relative } = safeArchivePath(rawName, expectedRoot);
    if (seen.has(normalized)) {
      throw new SetupError(`release tar stream contains duplicate entry ${normalized}`);
    }
    seen.add(normalized);

    const mode = parseOctal(header.subarray(100, 108), `mode for ${normalized}`);
    const uid = parseOctal(header.subarray(108, 116), `uid for ${normalized}`);
    const gid = parseOctal(header.subarray(116, 124), `gid for ${normalized}`);
    const size = parseOctal(header.subarray(124, 136), `size for ${normalized}`);
    const uname = decodeString(header.subarray(265, 297), `owner for ${normalized}`);
    const gname = decodeString(header.subarray(297, 329), `group for ${normalized}`);
    if (uid !== 0 || gid !== 0 || uname !== 'root' || gname !== 'root') {
      throw new SetupError(`release tar entry ${normalized} has non-canonical ownership`);
    }
    const typeByte = header[156] ?? 0;
    let type: 'file' | 'directory';
    if (typeByte === 0 || typeByte === 0x30) {
      type = 'file';
    } else if (typeByte === 0x35) {
      type = 'directory';
    } else {
      throw new SetupError(`release tar entry ${normalized} is a link or special file`);
    }
    if (type === 'directory' && size !== 0) {
      throw new SetupError(`release tar directory ${normalized} has a nonzero size`);
    }
    if (type === 'file' && size > MAX_FILE_BYTES) {
      throw new SetupError(`release tar file ${normalized} exceeds ${MAX_FILE_BYTES} bytes`);
    }
    if (relative.length === 0 && type !== 'directory') {
      throw new SetupError('release archive top-level entry is not a directory');
    }

    const expectedMode = type === 'directory' || relative === 'bin/debz' ? 0o755 : 0o644;
    if (mode !== expectedMode) {
      throw new SetupError(
        `release tar entry ${normalized} has mode ${mode.toString(8)}, expected ${expectedMode.toString(8)}`,
      );
    }
    if (relative === 'bin' && type !== 'directory') {
      throw new SetupError('release archive bin entry is not a directory');
    }
    if (relative.startsWith('bin/') && relative !== 'bin/debz') {
      throw new SetupError(`release archive contains unexpected PATH entry ${relative}`);
    }
    if (relative === 'bin/debz' && type !== 'file') {
      throw new SetupError('release archive bin/debz entry is not a regular file');
    }
    if (relative === 'bin/debz' && size === 0) {
      throw new SetupError('release archive bin/debz entry is empty');
    }

    const dataOffset = offset + TAR_BLOCK_SIZE;
    const paddedSize = Math.ceil(size / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;
    const nextOffset = dataOffset + paddedSize;
    if (nextOffset > tar.length) {
      throw new SetupError(`release tar entry ${normalized} is truncated`);
    }
    const data = type === 'file' ? tar.subarray(dataOffset, dataOffset + size) : undefined;
    const entry: ArchiveEntry = {
      relativePath: relative,
      type,
      mode: expectedMode,
      ...(data ? { data } : {}),
    };
    entries.push(entry);
    if (relative === 'bin/debz' && data) {
      binary = data;
    }
    offset = nextOffset;
  }

  if (zeroBlocks < 2) {
    throw new SetupError('release tar stream has no complete end marker');
  }
  if (!seen.has(expectedRoot) || !entries.some((entry) => entry.relativePath === 'bin')) {
    throw new SetupError('release archive is missing its expected root or bin directory');
  }
  if (!binary) {
    throw new SetupError('release archive is missing bin/debz');
  }
  return {
    entries,
    binary,
    binaryDigest: sha256Bytes(binary),
  };
}

async function pathExists(candidate: string): Promise<boolean> {
  try {
    await lstat(candidate);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return false;
    }
    throw error;
  }
}

async function writeManifest(root: string, archive: Buffer, manifest: ArchiveManifest): Promise<void> {
  for (const entry of manifest.entries) {
    const destination = entry.relativePath ? path.join(root, entry.relativePath) : root;
    if (entry.type === 'directory') {
      await mkdir(destination, { recursive: true, mode: entry.mode });
      await chmod(destination, entry.mode);
      continue;
    }
    await mkdir(path.dirname(destination), { recursive: true, mode: 0o755 });
    await writeFile(destination, entry.data as Buffer, {
      flag: 'wx',
      mode: entry.mode,
    });
    await chmod(destination, entry.mode);
  }
  await writeFile(path.join(root, CACHED_ARCHIVE_NAME), archive, {
    flag: 'wx',
    mode: 0o600,
  });
}

export async function publishArchive(
  archive: Buffer,
  expectedRoot: string,
  finalRoot: string,
): Promise<'published' | 'raced'> {
  const manifest = parseArchive(archive, expectedRoot);
  const parent = path.dirname(finalRoot);
  await mkdir(parent, { recursive: true, mode: 0o755 });
  const staging = path.join(parent, `.stage-${process.pid}-${randomUUID()}`);
  await mkdir(staging, { mode: 0o700 });
  try {
    await writeManifest(staging, archive, manifest);
    try {
      await rename(staging, finalRoot);
      return 'published';
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'EEXIST' || code === 'ENOTEMPTY') {
        return 'raced';
      }
      throw error;
    }
  } finally {
    if (await pathExists(staging)) {
      await rm(staging, { recursive: true, force: true });
    }
  }
}

async function collectTree(root: string, relative = ''): Promise<Map<string, Stats>> {
  const result = new Map<string, Stats>();
  const directory = relative ? path.join(root, relative) : root;
  for (const name of await readdir(directory)) {
    if (relative.length === 0 && name === CACHED_ARCHIVE_NAME) {
      continue;
    }
    const childRelative = relative ? `${relative}/${name}` : name;
    const child = path.join(root, childRelative);
    const info = await lstat(child);
    result.set(childRelative, info);
    if (info.isDirectory()) {
      for (const [nestedPath, nestedInfo] of await collectTree(root, childRelative)) {
        result.set(nestedPath, nestedInfo);
      }
    }
  }
  return result;
}

export async function verifyCachedInstallation(
  finalRoot: string,
  expectedRoot: string,
  expectedArchiveSize: number,
  expectedArchiveDigest: string,
): Promise<{ executablePath: string; binaryDigest: string }> {
  const rootInfo = await lstat(finalRoot);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink() || (rootInfo.mode & 0o777) !== 0o755) {
    throw new SetupError('cached installation root is not a mode-755 directory');
  }
  const archivePath = path.join(finalRoot, CACHED_ARCHIVE_NAME);
  const archiveInfo = await lstat(archivePath);
  if (!archiveInfo.isFile() || archiveInfo.isSymbolicLink()) {
    throw new SetupError('cached release archive is not a regular file');
  }
  if (archiveInfo.size !== expectedArchiveSize) {
    throw new SetupError(
      `cached release archive size mismatch: expected ${expectedArchiveSize}, found ${archiveInfo.size}`,
    );
  }
  const archive = await readFile(archivePath);
  const actualArchiveDigest = sha256Bytes(archive);
  if (actualArchiveDigest !== expectedArchiveDigest) {
    throw new SetupError(
      `cached release archive SHA-256 mismatch: expected ${expectedArchiveDigest}, found ${actualArchiveDigest}`,
    );
  }
  const manifest = parseArchive(archive, expectedRoot);
  const expectedEntries = new Map(
    manifest.entries
      .filter((entry) => entry.relativePath.length > 0)
      .map((entry) => [entry.relativePath, entry]),
  );
  const actualEntries = await collectTree(finalRoot);
  if (
    actualEntries.size !== expectedEntries.size ||
    [...actualEntries.keys()].some((name) => !expectedEntries.has(name))
  ) {
    throw new SetupError('cached installation layout differs from the authenticated archive');
  }
  for (const [relative, entry] of expectedEntries) {
    const info = actualEntries.get(relative);
    if (!info) {
      throw new SetupError(`cached installation is missing ${relative}`);
    }
    const actualMode = info.mode & 0o777;
    if (actualMode !== entry.mode) {
      throw new SetupError(
        `cached installation mode mismatch for ${relative}: expected ${entry.mode.toString(8)}, found ${actualMode.toString(8)}`,
      );
    }
    if (entry.type === 'directory') {
      if (!info.isDirectory() || info.isSymbolicLink()) {
        throw new SetupError(`cached installation ${relative} is not a directory`);
      }
      continue;
    }
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new SetupError(`cached installation ${relative} is not a regular file`);
    }
    const data = await readFile(path.join(finalRoot, relative));
    if (!(entry.data as Buffer).equals(data)) {
      throw new SetupError(`cached installation content mismatch for ${relative}`);
    }
  }
  return {
    executablePath: path.join(finalRoot, 'bin', 'debz'),
    binaryDigest: manifest.binaryDigest,
  };
}

export async function exists(candidate: string): Promise<boolean> {
  return await pathExists(candidate);
}
