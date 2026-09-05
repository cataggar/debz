import assert from 'node:assert/strict';
import { chmod, lstat, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { runAction, runMain } from '../src/action.js';
import type { CacheAdapter } from '../src/cache.js';
import { readInputs } from '../src/inputs.js';
import { environment, fingerprint, preparation } from './helpers.js';

const testRoot = path.resolve(process.cwd(), '../../.tmp/download-action-tests/action');
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

async function fakeDebz(values: ReturnType<typeof environment>): Promise<{
  bin: string;
  executable: string;
  log: string;
  expected: ReturnType<typeof fingerprint>;
  prepared: ReturnType<typeof preparation>;
}> {
  const inputs = await readInputs(values);
  const expected = fingerprint(inputs);
  const prepared = preparation(inputs, expected);
  const bin = path.join(testRoot, 'bin');
  await mkdir(bin);
  const executable = path.join(bin, 'debz');
  const log = path.join(testRoot, 'debz.log');
  await writeFile(log, '');
  await writeFile(
    executable,
    `#!/bin/sh
printf '%s\\n' "$2" >>'${log}'
if [ "$1" = version ]; then
  printf '0.3.0\\n'
elif [ "$2" = fingerprint ]; then
  printf '%s\\n' '${JSON.stringify(expected)}'
elif [ "$2" = prepare ]; then
  printf '%s\\n' '${JSON.stringify(prepared)}'
else
  exit 2
fi
`,
  );
  await chmod(executable, 0o755);
  return { bin, executable, log, expected, prepared };
}

function installEnvironment(
  values: ReturnType<typeof environment>,
  bin: string,
  outputPath: string,
): NodeJS.ProcessEnv {
  const previous = { ...process.env };
  Object.assign(process.env, values, {
    PATH: bin,
    GITHUB_OUTPUT: outputPath,
  });
  return previous;
}

function restoreEnvironment(previous: NodeJS.ProcessEnv): void {
  for (const key of Object.keys(process.env)) {
    if (!(key in previous)) delete process.env[key];
  }
  Object.assign(process.env, previous);
  process.exitCode = undefined;
}

test('restores, prepares, saves a partial cache, and publishes outputs last', async () => {
  const values = environment(workspace, runnerTemp);
  const inputs = await readInputs(values);
  const { bin, expected } = await fakeDebz(values);
  const outputPath = path.join(testRoot, 'github-output');
  await writeFile(outputPath, '');

  const previous = installEnvironment(values, bin, outputPath);
  let restored = false;
  let saved = false;
  let restoredPath = '';
  let savedPath = '';
  const cache: CacheAdapter = {
    isFeatureAvailable() {
      return true;
    },
    async restore(destination, primaryKey, restorePrefix, maximumBytes) {
      restored = true;
      restoredPath = destination;
      assert.notEqual(destination, inputs.cachePath);
      assert.equal(path.basename(destination), 'restored.dbzcache');
      assert.ok(destination.startsWith(`${runnerTemp}${path.sep}`));
      assert.equal(primaryKey, expected.primary_key);
      assert.equal(restorePrefix, expected.restore_prefix);
      assert.ok(maximumBytes > inputs.limits.maximumTotalPackageBytes);
      await writeFile(destination, 'opaque cache bytes');
      return `${restorePrefix}${'d'.repeat(64)}`;
    },
    async save(source, primaryKey, maximumBytes) {
      saved = true;
      savedPath = source;
      assert.notEqual(source, inputs.cachePath);
      assert.equal(path.basename(source), 'export.dbzcache');
      assert.ok(source.startsWith(`${runnerTemp}${path.sep}`));
      assert.equal(primaryKey, expected.primary_key);
      assert.ok(maximumBytes > inputs.limits.maximumTotalPackageBytes);
    },
  };

  try {
    process.exitCode = undefined;
    await runMain(cache);
    assert.equal(process.exitCode, undefined);
    assert.equal(restored, true);
    assert.equal(saved, true);
    await assert.rejects(lstat(restoredPath));
    await assert.rejects(lstat(savedPath));
    const output = await readFile(outputPath, 'utf8');
    assert.match(output, /cache-hit<<[^\n]+\nfalse\n/);
    assert.match(output, /cache-matched-key<<[^\n]+\ndebz-package-cas-v1-/);
    assert.match(output, /downloaded-count<<[^\n]+\n1\n/);
    assert.match(output, /reused-count<<[^\n]+\n2\n/);
  } finally {
    restoreEnvironment(previous);
  }
});

test('an exact cache match still prepares and never saves', async () => {
  const values = environment(workspace, runnerTemp);
  const { bin, expected } = await fakeDebz(values);
  const outputPath = path.join(testRoot, 'github-output');
  await writeFile(outputPath, '');
  const previous = installEnvironment(values, bin, outputPath);
  let saved = false;
  const cache: CacheAdapter = {
    isFeatureAvailable() {
      return true;
    },
    async restore(destination) {
      await writeFile(destination, 'opaque cache bytes');
      return expected.primary_key;
    },
    async save() {
      saved = true;
    },
  };

  try {
    process.exitCode = undefined;
    await runMain(cache);
    assert.equal(process.exitCode, undefined);
    assert.equal(saved, false);
    const output = await readFile(outputPath, 'utf8');
    assert.match(output, /cache-hit<<[^\n]+\ntrue\n/);
    assert.match(output, /downloaded-count<<[^\n]+\n1\n/);
  } finally {
    restoreEnvironment(previous);
  }
});

test('a cache restore cannot replace debz before prepare', async () => {
  const values = environment(workspace, runnerTemp);
  const { bin, executable, log, expected } = await fakeDebz(values);
  const outputPath = path.join(testRoot, 'github-output');
  await writeFile(outputPath, '');
  const previous = installEnvironment(values, bin, outputPath);
  const cache: CacheAdapter = {
    isFeatureAvailable() {
      return true;
    },
    async restore(destination) {
      await writeFile(destination, 'opaque cache bytes');
      await writeFile(
        executable,
        '#!/bin/sh\nprintf \"replacement executed\\n\" >>\"' + log + '\"\nexit 1\n',
      );
      await chmod(executable, 0o755);
      return `${expected.restore_prefix}${'d'.repeat(64)}`;
    },
    async save() {
      assert.fail('save must not run after executable replacement');
    },
  };

  try {
    process.exitCode = undefined;
    await assert.rejects(
      runAction(cache),
      /executable changed after its package-cache fingerprint/,
    );
    assert.equal(await readFile(outputPath, 'utf8'), '');
    const invocations = (await readFile(log, 'utf8')).trim().split('\n');
    assert.ok(invocations.includes('fingerprint'));
    assert.ok(!invocations.includes('prepare'));
    assert.ok(!invocations.includes('replacement executed'));
  } finally {
    restoreEnvironment(previous);
  }
});
