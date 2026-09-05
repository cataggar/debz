import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';

import { InstallActionError } from './errors.js';

const maximumProtectedFileBytes = 128 * 1024 * 1024;

export interface FileIdentity {
  path: string;
  device: bigint;
  inode: bigint;
  size: bigint;
  mode: bigint;
  sha256: string;
}

export interface DirectoryIdentity {
  path: string;
  device: bigint;
  inode: bigint;
}

export interface OptionalFileIdentity {
  path: string;
  exists: boolean;
  device?: bigint;
  inode?: bigint;
  size?: bigint;
  mtimeNs?: bigint;
}

export async function captureFileIdentity(filename: string): Promise<FileIdentity> {
  const resolved = await realpath(filename);
  if (resolved !== path.resolve(filename)) {
    throw new InstallActionError('protected input path changed or became a symbolic link');
  }
  const handle = await open(
    filename,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
  );
  try {
    const details = await handle.stat({ bigint: true });
    if (
      !details.isFile() ||
      details.size < 0 ||
      details.size > BigInt(maximumProtectedFileBytes)
    ) {
      throw new InstallActionError('protected input is not a bounded regular file');
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let offset = 0;
    while (offset < Number(details.size)) {
      const read = await handle.read(
        buffer,
        0,
        Math.min(buffer.length, Number(details.size) - offset),
        offset,
      );
      if (read.bytesRead === 0) break;
      hash.update(buffer.subarray(0, read.bytesRead));
      offset += read.bytesRead;
    }
    if (offset !== Number(details.size)) {
      throw new InstallActionError('protected input changed while it was read');
    }
    return {
      path: filename,
      device: details.dev,
      inode: details.ino,
      size: details.size,
      mode: details.mode,
      sha256: hash.digest('hex'),
    };
  } finally {
    await handle.close();
  }
}

export async function verifyFileIdentity(expected: FileIdentity): Promise<void> {
  const current = await captureFileIdentity(expected.path);
  if (
    current.device !== expected.device ||
    current.inode !== expected.inode ||
    current.size !== expected.size ||
    current.mode !== expected.mode ||
    current.sha256 !== expected.sha256
  ) {
    throw new InstallActionError(
      'a lock, repository, keyring, or credential input changed during installation',
    );
  }
}

export async function captureDirectoryIdentity(
  directory: string,
): Promise<DirectoryIdentity> {
  const resolved = await realpath(directory);
  const details = await lstat(directory, { bigint: true });
  if (
    resolved !== path.resolve(directory) ||
    !details.isDirectory() ||
    details.isSymbolicLink()
  ) {
    throw new InstallActionError('mutable path is not a canonical directory');
  }
  return {
    path: directory,
    device: details.dev,
    inode: details.ino,
  };
}

export async function verifyDirectoryIdentity(
  expected: DirectoryIdentity,
): Promise<void> {
  const current = await captureDirectoryIdentity(expected.path);
  if (current.device !== expected.device || current.inode !== expected.inode) {
    throw new InstallActionError('a mutable root changed identity during installation');
  }
}

export async function captureOptionalFileIdentity(
  filename: string,
): Promise<OptionalFileIdentity> {
  try {
    const details = await lstat(filename, { bigint: true });
    if (!details.isFile() || details.isSymbolicLink()) {
      throw new InstallActionError(
        'transaction-result path must be absent or a regular non-symbolic file',
      );
    }
    return {
      path: filename,
      exists: true,
      device: details.dev,
      inode: details.ino,
      size: details.size,
      mtimeNs: details.mtimeNs,
    };
  } catch (error) {
    if (error instanceof InstallActionError) throw error;
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return { path: filename, exists: false };
    }
    throw error;
  }
}

export async function requireFreshResult(
  before: OptionalFileIdentity,
): Promise<OptionalFileIdentity> {
  const after = await captureOptionalFileIdentity(before.path);
  if (!after.exists) {
    throw new InstallActionError('debz did not write transaction-result.json');
  }
  if (
    before.exists &&
    before.device === after.device &&
    before.inode === after.inode
  ) {
    throw new InstallActionError(
      'debz did not atomically replace the prior transaction result',
    );
  }
  return after;
}

export async function verifyOptionalFileIdentity(
  expected: OptionalFileIdentity,
): Promise<void> {
  const current = await captureOptionalFileIdentity(expected.path);
  if (
    !expected.exists ||
    !current.exists ||
    expected.device !== current.device ||
    expected.inode !== current.inode ||
    expected.size !== current.size ||
    expected.mtimeNs !== current.mtimeNs
  ) {
    throw new InstallActionError(
      'transaction-result.json changed during final verification',
    );
  }
}
