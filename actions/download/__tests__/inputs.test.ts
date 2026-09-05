import assert from 'node:assert/strict';
import { chmod, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { environment } from './helpers.js';
import { findDebz, readInputs } from '../src/inputs.js';

const testRoot = path.resolve(process.cwd(), '../../.tmp/download-action-tests/inputs');
const workspace = path.join(testRoot, 'workspace');
const runnerTemp = path.join(testRoot, 'runner');

test.beforeEach(async () => {
  await rm(testRoot, { recursive: true, force: true });
  await mkdir(workspace, { recursive: true });
  await mkdir(runnerTemp, { recursive: true });
  await writeFile(path.join(workspace, 'lock.json'), '{}\n');
  await writeFile(path.join(workspace, 'repo.sources'), 'Types: deb\n');
  await writeFile(path.join(workspace, 'keyring.gpg'), 'keyring');
});

test.after(async () => {
  await rm(testRoot, { recursive: true, force: true });
});

test('resolves explicit files and creates only the package object cache path', async () => {
  const values = environment(workspace, runnerTemp);
  values.DEBZ_DOWNLOAD_FOREIGN_ARCHITECTURE = 'arm64';
  values.DEBZ_DOWNLOAD_CACHE = 'false';
  const inputs = await readInputs(values);
  assert.equal(inputs.lockInput, path.join(workspace, 'lock.json'));
  assert.deepEqual(inputs.foreignArchitectures, ['arm64']);
  assert.equal(inputs.cacheEnabled, false);
  assert.equal(
    inputs.cachePath,
    path.join(runnerTemp, 'debz-package-cache', 'packages-v1', 'objects'),
  );
});

test('reads standard JavaScript-action INPUT_* environment names', async () => {
  const values = environment(workspace, runnerTemp);
  for (const key of Object.keys(values)) {
    if (!key.startsWith('DEBZ_DOWNLOAD_')) continue;
    const value = values[key];
    delete values[key];
    values[`INPUT_${key.slice('DEBZ_DOWNLOAD_'.length).replaceAll('_', '-')}`] = value;
  }
  const inputs = await readInputs(values);
  assert.equal(inputs.lockInput, path.join(workspace, 'lock.json'));
  assert.equal(inputs.cacheEnabled, true);
  assert.equal(inputs.architecture, 'amd64');
});

test('rejects traversal, symlinked inputs, cache overlap, and credential-bearing proxy', async () => {
  const traversal = environment(workspace, runnerTemp);
  traversal.DEBZ_DOWNLOAD_LOCK_INPUT = '../lock.json';
  await assert.rejects(readInputs(traversal), /ambiguous path component|escapes/);

  await symlink(path.join(workspace, 'lock.json'), path.join(workspace, 'linked-lock'));
  const linked = environment(workspace, runnerTemp);
  linked.DEBZ_DOWNLOAD_LOCK_INPUT = 'linked-lock';
  await assert.rejects(readInputs(linked), /symbolic link/);

  const proxy = environment(workspace, runnerTemp);
  proxy.DEBZ_DOWNLOAD_PROXY = 'https://user:secret@example.invalid';
  await assert.rejects(readInputs(proxy), /without credentials/);

  const overlapping = environment(workspace, runnerTemp);
  const nested = path.join(runnerTemp, 'cache', 'lock.json');
  await mkdir(path.dirname(nested), { recursive: true });
  await writeFile(nested, '{}\n');
  overlapping.DEBZ_DOWNLOAD_LOCK_INPUT = nested;
  overlapping.DEBZ_DOWNLOAD_CACHE_ROOT = path.join(runnerTemp, 'cache');
  await assert.rejects(readInputs(overlapping), /must be outside cache-root/);
});

test('rejects contradictory and unbounded policy values before cache restore', async () => {
  const repairOffline = environment(workspace, runnerTemp);
  repairOffline.DEBZ_DOWNLOAD_OFFLINE = 'true';
  repairOffline.DEBZ_DOWNLOAD_REPAIR_CORRUPT_CACHE = 'true';
  await assert.rejects(readInputs(repairOffline), /cannot be enabled/);

  const invalidBoolean = environment(workspace, runnerTemp);
  invalidBoolean.DEBZ_DOWNLOAD_CACHE = 'yes';
  await assert.rejects(readInputs(invalidBoolean), /exactly 'true' or 'false'/);

  const unbounded = environment(workspace, runnerTemp);
  unbounded.DEBZ_DOWNLOAD_MAXIMUM_LOCK_PACKAGES = '1000001';
  await assert.rejects(readInputs(unbounded), /bounded maximum/);

  await assert.rejects(
    readInputs(environment(workspace, runnerTemp), {
      platform: 'darwin',
      architecture: 'x64',
    }),
    /unsupported runner/,
  );
  const unsupportedTarget = environment(workspace, runnerTemp);
  unsupportedTarget.DEBZ_DOWNLOAD_ARCHITECTURE = 'riscv64';
  await assert.rejects(readInputs(unsupportedTarget), /invalid target architecture/);
});

test('accepts only a regular executable debz from absolute PATH entries', async () => {
  const bin = path.join(testRoot, 'bin');
  await mkdir(bin);
  const executable = path.join(bin, 'debz');
  await writeFile(executable, '#!/bin/sh\nexit 0\n');
  await chmod(executable, 0o755);
  assert.equal(await findDebz({ PATH: bin }), executable);

  await rm(executable);
  await symlink('/bin/true', executable);
  await assert.rejects(findDebz({ PATH: bin }), /was not found/);
  await assert.rejects(findDebz({ PATH: `relative${path.delimiter}${bin}` }), /was not found/);
});
