import assert from 'node:assert/strict';
import { lstat, mkdir, rm, symlink } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { createInputEnvironment, testRoot } from './helpers.js';
import { prepareDirectories, readInputs } from '../src/inputs.js';

test.after(async () => {
  await rm(testRoot, { recursive: true, force: true });
});

test('validates all typed inputs before creating mutable directories', async () => {
  const fixture = await createInputEnvironment('valid');
  fixture.environment.DEBZ_INSTALL_FORCE = 'depends\noverwrite_dir';
  fixture.environment.DEBZ_INSTALL_STATE_PATH = '';
  const inputs = await readInputs(fixture.environment);
  assert.deepEqual(inputs.forces, ['depends', 'overwrite_dir']);
  assert.match(inputs.statePath, /debz-install-state\/[0-9a-f]{32}$/u);
  await assert.rejects(lstat(inputs.installRoot), /ENOENT/u);
  await prepareDirectories(inputs);
  assert.equal((await lstat(inputs.installRoot)).isDirectory(), true);
  assert.equal((await lstat(inputs.statePath)).isDirectory(), true);
  assert.equal((await lstat(inputs.cacheRoot)).isDirectory(), true);
});

test('rejects host root, wrong architecture, unsafe booleans, and bad selectors', async () => {
  const root = await createInputEnvironment('root');
  root.environment.DEBZ_INSTALL_INSTALL_ROOT = '/';
  await assert.rejects(readInputs(root.environment), /host root/u);

  const architecture = await createInputEnvironment('architecture');
  architecture.environment.DEBZ_INSTALL_ARCHITECTURE = 'arm64';
  await assert.rejects(readInputs(architecture.environment), /native amd64/u);

  const mutation = await createInputEnvironment('mutation');
  mutation.environment.DEBZ_INSTALL_ASSUME_YES = 'yes';
  await assert.rejects(readInputs(mutation.environment), /exactly 'true'/u);

  const whitespace = await createInputEnvironment('whitespace');
  whitespace.environment.DEBZ_INSTALL_USE_SUDO = ' true ';
  await assert.rejects(readInputs(whitespace.environment), /exact single-line/u);

  const cacheOnly = await createInputEnvironment('cache-only');
  cacheOnly.environment.DEBZ_INSTALL_OFFLINE = 'true';
  cacheOnly.environment.DEBZ_INSTALL_CACHE_ONLY = 'yes';
  await assert.rejects(readInputs(cacheOnly.environment), /exactly 'true' or 'false'/u);

  const selector = await createInputEnvironment('selector');
  selector.environment.DEBZ_INSTALL_PACKAGE = '--option';
  await assert.rejects(readInputs(selector.environment), /install selector/u);

  const longSelector = await createInputEnvironment('long-selector');
  longSelector.environment.DEBZ_INSTALL_PACKAGE = `${'a'.repeat(128)}:${'a'.repeat(32)}=${'1'.repeat(128)}`;
  await assert.rejects(readInputs(longSelector.environment), /install selector/u);

  const oldVersion = await createInputEnvironment('old-version');
  oldVersion.environment.DEBZ_INSTALL_DEBZ_VERSION = 'v0.2.0';
  await assert.rejects(readInputs(oldVersion.environment), /v0\.3\.0 or newer/u);
});

test('rejects symlinked and overlapping mutable roots before setup', async () => {
  const linked = await createInputEnvironment('linked');
  const realRoot = path.join(linked.runner, 'real-root');
  await prepareDirectories({
    ...(await readInputs(linked.environment)),
    installRoot: realRoot,
  });
  const link = path.join(linked.runner, 'linked-root');
  await symlink(realRoot, link);
  linked.environment.DEBZ_INSTALL_INSTALL_ROOT = link;
  await assert.rejects(readInputs(linked.environment), /symbolic link/u);

  const cacheLinked = await createInputEnvironment('cache-linked');
  const cacheRoot = cacheLinked.environment.DEBZ_INSTALL_CACHE_ROOT as string;
  const realObjects = path.join(cacheLinked.runner, 'real-objects');
  await mkdir(path.join(cacheRoot, 'packages-v1'), { recursive: true });
  await mkdir(realObjects);
  await symlink(realObjects, path.join(cacheRoot, 'packages-v1', 'objects'));
  await assert.rejects(readInputs(cacheLinked.environment), /symbolic link/u);

  const overlap = await createInputEnvironment('overlap');
  overlap.environment.DEBZ_INSTALL_STATE_PATH =
    overlap.environment.DEBZ_INSTALL_INSTALL_ROOT;
  await assert.rejects(readInputs(overlap.environment), /must not overlap/u);
});

test('invalid late policy input creates no selected root', async () => {
  const fixture = await createInputEnvironment('no-side-effects');
  const root = fixture.environment.DEBZ_INSTALL_INSTALL_ROOT as string;
  fixture.environment.DEBZ_INSTALL_CLI_CACHE = 'enabled';
  await assert.rejects(readInputs(fixture.environment), /exactly 'true' or 'false'/u);
  await assert.rejects(lstat(root), /ENOENT/u);
});
