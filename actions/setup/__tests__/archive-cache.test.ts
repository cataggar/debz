import assert from 'node:assert/strict';
import { chmod, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  CACHED_ARCHIVE_NAME,
  parseArchive,
  publishArchive,
  verifyCachedInstallation,
} from '../src/archive.js';
import { sha256Bytes } from '../src/hash.js';
import { makeArchive } from './helpers.js';

const rootName = 'debz-1.2.3-linux-x64';
const testRoot = path.resolve(process.cwd(), '../../.tmp/setup-action-tests/archive-cache');

test.before(async () => {
  await rm(testRoot, { recursive: true, force: true });
  await mkdir(testRoot, { recursive: true });
});

test.after(async () => {
  await rm(testRoot, { recursive: true, force: true });
});

test('strict archive parser accepts the expected release layout', () => {
  const manifest = parseArchive(makeArchive(rootName), rootName);
  assert.equal(manifest.binary.toString(), 'test debz executable\n');
  assert.equal(manifest.entries.filter((entry) => entry.relativePath === 'bin/debz').length, 1);
});

test('archive parser rejects traversal, absolute paths, links, devices, and duplicate entries', () => {
  const cases = [
    {
      archive: makeArchive(rootName, [
        { name: `${rootName}/share/../escape`, type: '0', data: Buffer.from('x') },
      ]),
      error: /unsafe archive path/,
    },
    {
      archive: makeArchive(rootName, [
        { name: '/absolute', type: '0', data: Buffer.from('x') },
      ]),
      error: /unsafe archive path/,
    },
    {
      archive: makeArchive(rootName, [{ name: `${rootName}/share/link`, type: '2' }]),
      error: /link or special file/,
    },
    {
      archive: makeArchive(rootName, [{ name: `${rootName}/share/device`, type: '3' }]),
      error: /link or special file/,
    },
    {
      archive: makeArchive(rootName, [
        {
          name: `${rootName}/bin/debz`,
          type: '0',
          mode: 0o755,
          data: Buffer.from('duplicate'),
        },
      ]),
      error: /duplicate entry/,
    },
  ];
  for (const candidate of cases) {
    assert.throws(() => parseArchive(candidate.archive, rootName), candidate.error);
  }
});

test('archive parser rejects extra PATH entries and noncanonical modes', () => {
  assert.throws(
    () =>
      parseArchive(
        makeArchive(rootName, [
          {
            name: `${rootName}/bin/curl`,
            type: '0',
            mode: 0o644,
            data: Buffer.from('shadow'),
          },
        ]),
        rootName,
      ),
    /unexpected PATH entry/,
  );
  const archive = makeArchive(rootName, [
    {
      name: `${rootName}/share/bad`,
      type: '0',
      mode: 0o777,
      data: Buffer.from('bad'),
    },
  ]);
  assert.throws(() => parseArchive(archive, rootName), /mode 777/);
});

test('gzip streams with trailing data are rejected', () => {
  const archive = Buffer.concat([makeArchive(rootName), Buffer.from('trailing')]);
  assert.throws(() => parseArchive(archive, rootName), /trailing|CRC-32|invalid/);
});

test('published installations are exact and reverified against the archive', async () => {
  const archive = makeArchive(rootName);
  const digest = sha256Bytes(archive);
  const destination = path.join(testRoot, 'valid');
  assert.equal(await publishArchive(archive, rootName, destination), 'published');
  const result = await verifyCachedInstallation(
    destination,
    rootName,
    archive.length,
    digest,
  );
  assert.equal(result.executablePath, path.join(destination, 'bin', 'debz'));
  assert.equal((await readFile(result.executablePath)).toString(), 'test debz executable\n');
});

test('cache archive corruption fails instead of triggering an unverified fallback', async () => {
  const archive = makeArchive(rootName);
  const destination = path.join(testRoot, 'archive-corrupt');
  await publishArchive(archive, rootName, destination);
  const archivePath = path.join(destination, CACHED_ARCHIVE_NAME);
  const corrupted = await readFile(archivePath);
  corrupted[corrupted.length - 1] ^= 0xff;
  await writeFile(archivePath, corrupted);
  await assert.rejects(
    verifyCachedInstallation(destination, rootName, archive.length, sha256Bytes(archive)),
    /SHA-256 mismatch/,
  );
});

test('cache executable corruption, unexpected files, and mode changes fail', async () => {
  const archive = makeArchive(rootName);
  const digest = sha256Bytes(archive);
  for (const kind of ['content', 'extra', 'mode'] as const) {
    const destination = path.join(testRoot, `tree-${kind}`);
    await publishArchive(archive, rootName, destination);
    if (kind === 'content') {
      await writeFile(path.join(destination, 'bin', 'debz'), 'tampered\n');
    } else if (kind === 'extra') {
      await writeFile(path.join(destination, 'bin', 'git'), 'shadow\n', { mode: 0o755 });
    } else {
      await chmod(path.join(destination, 'bin', 'debz'), 0o644);
    }
    await assert.rejects(
      verifyCachedInstallation(destination, rootName, archive.length, digest),
      /layout differs|content mismatch|mode mismatch/,
    );
  }
});
