import assert from 'node:assert/strict';
import { chmod, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { runMain } from '../src/action.js';
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
  expected: ReturnType<typeof fingerprint>;
  prepared: ReturnType<typeof preparation>;
}> {
  const inputs = await readInputs(values);
  const expected = fingerprint(inputs);
  const prepared = preparation(inputs, expected);
  const bin = path.join(testRoot, 'bin');
  await mkdir(bin);
  const executable = path.join(bin, 'debz');
  await writeFile(
    executable,
    `#!/bin/sh
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
  return { bin, expected, prepared };
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
  const cache: CacheAdapter = {
    isFeatureAvailable() {
      return true;
    },
    async restore(cachePath, primaryKey, restorePrefix) {
      restored = true;
      assert.equal(cachePath, inputs.cachePath);
      assert.equal(primaryKey, expected.primary_key);
      assert.equal(restorePrefix, expected.restore_prefix);
      return `${restorePrefix}${'d'.repeat(64)}`;
    },
    async save(cachePath, primaryKey) {
      saved = true;
      assert.equal(cachePath, inputs.cachePath);
      assert.equal(primaryKey, expected.primary_key);
    },
  };

  try {
    process.exitCode = undefined;
    await runMain(cache);
    assert.equal(process.exitCode, undefined);
    assert.equal(restored, true);
    assert.equal(saved, true);
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
    async restore() {
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
