import assert from 'node:assert/strict';
import test from 'node:test';

import { fingerprint, preparation } from './helpers.js';
import { requireNode24 } from '../src/action.js';
import type { Inputs } from '../src/inputs.js';
import {
  fingerprintArguments,
  fingerprintCache,
  prepareCache,
  readDebzVersion,
  restoredCacheState,
  validateFingerprint,
  validatePrepare,
  type CommandRunner,
} from '../src/runner.js';

const inputs: Inputs = {
  transactionBackend: 'legacy_dpkg',
  runnerTemp: '/runner',
  lockInput: '/workspace/lock.json',
  architecture: 'amd64',
  sources: ['/workspace/repo.sources'],
  configs: [],
  keyrings: ['/workspace/keyring.gpg'],
  foreignArchitectures: [],
  repositoryPolicy: 'strict-priority',
  recommends: false,
  allowDowngrade: false,
  lockWaitMs: 30_000,
  limits: {
    maximumPackageBytes: 1024,
    maximumTotalPackageBytes: 4096,
    maximumLockPackages: 10,
    maximumRepositoryRecords: 10,
    maximumStagingEntries: 10,
    maximumGcDirectoryEntries: 10,
    maximumGcObjectsScanned: 10,
    maximumGcObjectsDeleted: 10,
    maximumGcBytesDeleted: 4096,
  },
  cacheEnabled: true,
  cacheRoot: '/runner/cache',
  cachePath: '/runner/cache/packages-v1/objects',
  offline: false,
  repairCorruptCache: false,
};

test('requires the maintained Node 24 runtime', () => {
  assert.doesNotThrow(() => requireNode24('24.20.0'));
  assert.throws(() => requireNode24('22.0.0'), /requires the maintained Node 24/);
});

test('invokes debz without a shell and strictly validates both result schemas', async () => {
  const expected = fingerprint(inputs);
  const prepared = preparation(inputs, expected);
  const calls: string[][] = [];
  const runner: CommandRunner = {
    async run(_executable, arguments_) {
      calls.push(arguments_);
      if (arguments_[0] === 'version') return '0.3.0\n';
      if (arguments_[1] === 'fingerprint') return `${JSON.stringify(expected)}\n`;
      return `${JSON.stringify(prepared)}\n`;
    },
  };
  assert.equal(await readDebzVersion('/runner/debz', runner), '0.3.0');
  assert.deepEqual(
    await fingerprintCache('/runner/debz', '0.3.0', inputs, runner),
    expected,
  );
  assert.deepEqual(
    await prepareCache(
      '/runner/debz',
      '0.3.0',
      inputs,
      expected,
      {
        cacheHit: false,
        matchedKey: `${expected.restore_prefix}${'d'.repeat(64)}`,
        kind: 'partial',
      },
      {
        input: '/runner/restored.dbzcache',
        output: '/runner/export.dbzcache',
      },
      runner,
    ),
    prepared,
  );
  assert.equal(calls.length, 3);
  assert.equal(calls[1][0], 'package-cache');
  assert.equal(calls[1][1], 'fingerprint');
  assert.equal(calls[2][1], 'prepare');
  assert.ok(!calls[1].includes('--transaction-backend'));
  assert.ok(!calls[2].includes('--transaction-backend'));
  assert.ok(calls[2].includes('/workspace/keyring.gpg'));
  const restoreIndex = calls[2].indexOf('--restored-cache');
  assert.equal(calls[2][restoreIndex + 1], 'partial');
  assert.ok(calls[2].includes('/runner/restored.dbzcache'));
  assert.ok(calls[2].includes('/runner/export.dbzcache'));
});

test('native selection binds both commands and accepts only consistent v2 contracts', async () => {
  const nativeInputs: Inputs = { ...inputs, transactionBackend: 'native' };
  const expected = fingerprint(nativeInputs);
  const prepared = preparation(nativeInputs, expected);
  const calls: string[][] = [];
  const runner: CommandRunner = {
    async run(_executable, arguments_) {
      calls.push(arguments_);
      return `${JSON.stringify(arguments_[1] === 'fingerprint' ? expected : prepared)}\n`;
    },
  };
  assert.deepEqual(await fingerprintCache('/runner/debz', '0.3.0', nativeInputs, runner), expected);
  assert.deepEqual(await prepareCache(
    '/runner/debz', '0.3.0', nativeInputs, expected,
    { cacheHit: false, matchedKey: '', kind: 'none' }, {}, runner,
  ), prepared);
  for (const arguments_ of calls) {
    const index = arguments_.indexOf('--transaction-backend');
    assert.ok(index >= 0);
    assert.equal(arguments_[index + 1], 'native');
    assert.equal(arguments_.filter((argument) => argument === '--transaction-backend').length, 1);
  }
  assert.deepEqual(restoredCacheState(expected.primary_key, nativeInputs, expected), {
    cacheHit: true, matchedKey: expected.primary_key, kind: 'exact',
  });
  const partial = `${expected.restore_prefix}${'d'.repeat(64)}`;
  assert.deepEqual(restoredCacheState(partial, nativeInputs, expected), {
    cacheHit: false, matchedKey: partial, kind: 'partial',
  });
  assert.throws(() => restoredCacheState(fingerprint(inputs).primary_key, nativeInputs, expected), /outside/);
  assert.throws(() => restoredCacheState(expected.primary_key, inputs, fingerprint(inputs)), /outside/);
});

test('native and legacy schemas cannot be mixed or silently autodetected', async () => {
  const nativeInputs: Inputs = { ...inputs, transactionBackend: 'native' };
  const native = fingerprint(nativeInputs);
  const legacy = fingerprint(inputs);
  for (const [selected, foreign] of [[nativeInputs, legacy], [inputs, native]] as const) {
    let calls = 0;
    await assert.rejects(fingerprintCache('/runner/debz', '0.3.0', selected, {
      async run() {
        calls += 1;
        return `${JSON.stringify(foreign)}\n`;
      },
    }), /unexpected value/);
    assert.equal(calls, 1);
  }
  for (const field of [
    'schema', 'api_version', 'capability', 'lock_schema', 'lock_schema_version',
    'archive_format', 'origin_mode', 'primary_key', 'restore_prefix',
  ] as const) {
    assert.throws(
      () => validateFingerprint({ ...native, [field]: legacy[field] }, nativeInputs, '0.3.0'),
      /unexpected value|invalid/,
    );
  }
  const result = preparation(nativeInputs, native);
  const legacyResult = preparation(inputs, legacy);
  for (const field of ['schema', 'api_version', 'capability'] as const) {
    assert.throws(
      () => validatePrepare({ ...result, [field]: legacyResult[field] }, nativeInputs, native),
      /unexpected value/,
    );
  }
  await assert.rejects(prepareCache(
    '/runner/debz', '0.3.0', nativeInputs, legacy,
    { cacheHit: false, matchedKey: '', kind: 'none' }, {},
    { async run() { assert.fail('a foreign fingerprint must fail before invoking prepare'); } },
  ), /unexpected value/);
  await assert.rejects(fingerprintCache('/runner/debz', '0.3.0', nativeInputs, {
    async run() { throw new Error('unsupported native flag'); },
  }), /required package-cache-v2 fingerprint contract/);
});

test('zero verified objects are native-only and all counts remain consistent and bounded', () => {
  for (const transactionBackend of ['legacy_dpkg', 'native'] as const) {
    const selected: Inputs = { ...inputs, transactionBackend };
    const expected = fingerprint(selected);
    const empty = {
      ...preparation(selected, expected),
      downloaded_count: 0,
      reused_count: 0,
      verified_count: 0,
    };
    if (transactionBackend === 'native') {
      assert.deepEqual(validatePrepare(empty, selected, expected), empty);
    } else {
      assert.throws(() => validatePrepare(empty, selected, expected), /inconsistent counts/);
    }
    assert.throws(
      () => validatePrepare({ ...empty, reused_count: 1 }, selected, expected),
      /inconsistent counts/,
    );
    assert.throws(
      () => validatePrepare({ ...empty, reused_count: 11, verified_count: 11 }, selected, expected),
      /inconsistent counts/,
    );
  }
});

test('builds only typed arguments and excludes secrets from fingerprint material', () => {
  const withSecrets: Inputs = {
    ...inputs,
    proxy: 'https://proxy.example.invalid',
    credentialReference: '/runner/credential',
  };
  const arguments_ = fingerprintArguments(withSecrets);
  assert.ok(!arguments_.includes(withSecrets.proxy!));
  assert.ok(!arguments_.includes(withSecrets.credentialReference!));
  assert.ok(!arguments_.some((argument) => argument.includes('secret')));
  assert.ok(!arguments_.includes('--lock-wait-ms'));
  assert.ok(!arguments_.includes('--maximum-gc-objects-scanned'));
});

test('distinguishes exact, partial, miss, and disabled cache states', () => {
  const expected = fingerprint(inputs);
  assert.deepEqual(
    restoredCacheState(expected.primary_key, inputs, expected),
    { cacheHit: true, matchedKey: expected.primary_key, kind: 'exact' },
  );
  const partial = `${expected.restore_prefix}${'d'.repeat(64)}`;
  assert.deepEqual(
    restoredCacheState(partial, inputs, expected),
    { cacheHit: false, matchedKey: partial, kind: 'partial' },
  );
  assert.deepEqual(restoredCacheState(undefined, inputs, expected), {
    cacheHit: false,
    matchedKey: '',
    kind: 'none',
  });
  assert.deepEqual(
    restoredCacheState(
      'hostile-key',
      { ...inputs, cacheEnabled: false },
      expected,
    ),
    { cacheHit: false, matchedKey: '', kind: 'none' },
  );
});

test('rejects cache trust and output-shape contradictions', async () => {
  const expected = fingerprint(inputs);
  assert.equal(
    restoredCacheState(
      `${expected.restore_prefix}${'d'.repeat(64)}`,
      inputs,
      expected,
    ).cacheHit,
    false,
  );
  assert.throws(
    () =>
      restoredCacheState(
        'outside-prefix',
        inputs,
        expected,
      ),
    /outside/,
  );
  assert.throws(
      () =>
        restoredCacheState(
          `${expected.restore_prefix}${'d'.repeat(64)}\nforged`,
          inputs,
          expected,
        ),
      /multiline/,
  );

  const runner: CommandRunner = {
    async run() {
      return `${JSON.stringify({ ...expected, credential: 'secret' })}\n`;
    },
  };
  await assert.rejects(
    fingerprintCache('/runner/debz', '0.3.0', inputs, runner),
    /unsupported field set/,
  );
});

test('rejects malformed version, multiline JSON, and inconsistent counts', async () => {
  await assert.rejects(
    readDebzVersion('/runner/debz', {
      async run() {
        return '0.3.0\nextra\n';
      },
    }),
    /multiple lines/,
  );
  const expected = fingerprint(inputs);
  const invalid = { ...preparation(inputs, expected), verified_count: 4 };
  await assert.rejects(
    prepareCache(
      '/runner/debz',
      '0.3.0',
      inputs,
      expected,
      { cacheHit: false, matchedKey: '', kind: 'none' },
      {},
      {
        async run() {
          return `${JSON.stringify(invalid)}\n`;
        },
      },
    ),
    /inconsistent counts/,
  );
  await assert.rejects(
    fingerprintCache('/runner/debz', '0.3.0', inputs, {
      async run() {
        throw new Error('unknown command');
      },
    }),
    /required package-cache-v1 fingerprint contract/,
  );
});
