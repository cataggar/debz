import assert from 'node:assert/strict';
import { access, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { testRoot, fixtureInputs } from './helpers.js';
import {
  childEnvironment,
  parseCommandFile,
  runDebz,
  validateDownloadOutputs,
} from '../src/subprocess.js';

test('parses one-line file-command outputs and rejects output injection', () => {
  const names = new Set(['value']);
  assert.equal(
    parseCommandFile('value<<safe_delimiter\nexpected\nsafe_delimiter\n', names).get(
      'value',
    ),
    'expected',
  );
  assert.throws(
    () =>
      parseCommandFile(
        'value<<safe_delimiter\nfirst\ninjected=value\nsafe_delimiter\n',
        names,
      ),
    /one bounded line/u,
  );
  assert.throws(
    () =>
      parseCommandFile(
        'value<<safe_delimiter\nfirst\nsafe_delimiter\nvalue<<other\nsecond\nother\n',
        names,
      ),
    /duplicate/u,
  );
});

test('nested download handoff accepts only the explicitly selected cache key domain', () => {
  const inputs = fixtureInputs('/work');
  const outputs = new Map([
    ['cache-hit', 'true'],
    ['cache-matched-key', `debz-package-cas-v2-linux-x64-${'a'.repeat(64)}-${'b'.repeat(64)}`],
    ['cache-path', inputs.cachePath], ['cache-root', inputs.cacheRoot],
    ['lock-digest', 'a'.repeat(64)], ['downloaded-count', '0'], ['reused-count', '4'],
  ]);
  assert.throws(() => validateDownloadOutputs(outputs, inputs), /cache-hit evidence/u);
  inputs.transactionBackend = 'native';
  assert.equal(validateDownloadOutputs(outputs, inputs).reusedCount, 4);
  outputs.set('cache-matched-key', outputs.get('cache-matched-key')!.replace('-v2-', '-v1-'));
  assert.throws(() => validateDownloadOutputs(outputs, inputs), /cache-hit evidence/u);
});

test('isolates nested actions from install inputs and Node injection', () => {
  const original = {
    DEBZ_INSTALL_TOKEN: process.env.DEBZ_INSTALL_TOKEN,
    DEBZ_DOWNLOAD_TOKEN: process.env.DEBZ_DOWNLOAD_TOKEN,
    INPUT_TOKEN: process.env.INPUT_TOKEN,
    DEBZ_DOWNLOAD_TRANSACTION_BACKEND: process.env.DEBZ_DOWNLOAD_TRANSACTION_BACKEND,
    'INPUT_TRANSACTION-BACKEND': process.env['INPUT_TRANSACTION-BACKEND'],
    NODE_OPTIONS: process.env.NODE_OPTIONS,
  };
  try {
    process.env.DEBZ_INSTALL_TOKEN = 'install-secret';
    process.env.DEBZ_DOWNLOAD_TOKEN = 'download-secret';
    process.env.INPUT_TOKEN = 'ambient-secret';
    process.env.DEBZ_DOWNLOAD_TRANSACTION_BACKEND = 'native';
    process.env['INPUT_TRANSACTION-BACKEND'] = 'native';
    process.env.NODE_OPTIONS = '--require=/tmp/injected.js';
    const environment = childEnvironment({
      INPUT_TOKEN: 'intended-secret',
      DEBZ_DOWNLOAD_TRANSACTION_BACKEND: 'legacy_dpkg',
    });
    assert.equal(environment.DEBZ_INSTALL_TOKEN, undefined);
    assert.equal(environment.DEBZ_DOWNLOAD_TOKEN, undefined);
    assert.equal(environment.NODE_OPTIONS, undefined);
    assert.equal(environment.INPUT_TOKEN, 'intended-secret');
    assert.equal(environment.DEBZ_DOWNLOAD_TRANSACTION_BACKEND, 'legacy_dpkg');
    assert.equal(environment['INPUT_TRANSACTION-BACKEND'], undefined);
  } finally {
    for (const [name, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test('kills the complete debz process group when output exceeds its bound', async () => {
  const directory = path.join(testRoot, 'process-group');
  const marker = path.join(directory, 'orphaned-child');
  await mkdir(directory, { recursive: true });
  const descendant = [
    "const {writeFileSync}=require('node:fs');",
    `setTimeout(()=>writeFileSync(${JSON.stringify(marker)},'orphaned'),300);`,
  ].join('');
  const parent = [
    "const {spawn}=require('node:child_process');",
    `spawn(process.execPath,['-e',${JSON.stringify(descendant)}],{stdio:'ignore'});`,
    "process.stdout.write('x'.repeat(2048));",
    'setTimeout(()=>{},5000);',
  ].join('');
  await assert.rejects(
    runDebz(process.execPath, ['-e', parent], undefined, 1024),
    /output exceeded its bounded limit/u,
  );
  await new Promise((resolve) => setTimeout(resolve, 500));
  await assert.rejects(access(marker), /ENOENT/u);
  await rm(directory, { recursive: true, force: true });
});
