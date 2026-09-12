import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { runAction } from '../src/action.js';
import type { CacheAdapter } from '../src/cache.js';
import { environment } from './helpers.js';

test('native empty closures round-trip through the real CLI and opaque action cache', {
  skip: process.env.DEBZ_DOWNLOAD_INTEGRATION !== '1',
  timeout: 60_000,
}, async () => {
  const executable = process.env.DEBZ_DOWNLOAD_CLI;
  assert.ok(executable && path.isAbsolute(executable), 'DEBZ_DOWNLOAD_CLI must be absolute');
  const cli = await realpath(executable);
  const temporary = path.resolve(process.cwd(), '../../.tmp');
  await mkdir(temporary, { recursive: true });
  const root = await mkdtemp(path.join(temporary, 'native-download-action-'));
  const previous = { ...process.env };
  try {
    const workspace = path.join(root, 'workspace');
    const runnerTemp = path.join(root, 'runner');
    await mkdir(workspace);
    await mkdir(runnerTemp);
    const legacyPolicy = createHash('sha256')
      .update('debz-solver-policy-v1\0no-recommends\0no-downgrade\0strict_priority')
      .digest();
    const architecture = process.arch === 'arm64' ? 'arm64' : 'amd64';
    const lock = {
      schema: 'https://debz.dev/schema/exact-closure-lock-v2',
      version: 2,
      target_architecture: architecture,
      request_sha256: '1'.repeat(64),
      policy_sha256: createHash('sha256')
        .update('debz.product-native-solver-policy-v1\0')
        .update(legacyPolicy)
        .digest('hex'),
      repositories: [],
      local_artifacts: [],
      packages: [],
    };
    const digest = createHash('sha256').update(JSON.stringify(lock)).digest('hex');
    await writeFile(path.join(workspace, 'lock.json'), JSON.stringify({ ...lock, digest_sha256: digest }));
    const values = environment(workspace, runnerTemp);
    values.RUNNER_ARCH = architecture === 'arm64' ? 'ARM64' : 'X64';
    values.DEBZ_DOWNLOAD_ARCHITECTURE = architecture;
    values.DEBZ_DOWNLOAD_TRANSACTION_BACKEND = 'native';
    values.DEBZ_DOWNLOAD_SOURCE = '';
    values.DEBZ_DOWNLOAD_KEYRING = '';
    values.DEBZ_DOWNLOAD_OFFLINE = 'true';
    values.DEBZ_DOWNLOAD_EXECUTABLE = cli;
    let stored: { key: string; bytes: Buffer } | undefined;
    let saves = 0;
    const transferPaths: string[] = [];
    const cache: CacheAdapter = {
      isFeatureAvailable() { return true; },
      async restore(destination, key) {
        transferPaths.push(destination);
        if (stored === undefined) return undefined;
        assert.equal(key, stored.key);
        await writeFile(destination, stored.bytes);
        return stored.key;
      },
      async save(source, key) {
        transferPaths.push(source);
        const bytes = await readFile(source);
        const body = Buffer.concat([Buffer.from('debz-package-cache-archive-v2\n'), Buffer.alloc(4)]);
        assert.deepEqual(bytes, Buffer.concat([body, createHash('sha256').update(body).digest()]));
        assert.match(key, /^debz-package-cas-v2-/u);
        stored = { key, bytes };
        saves += 1;
      },
    };
    for (const phase of ['cold', 'exact'] as const) {
      const outputPath = path.join(root, `${phase}.outputs`);
      await writeFile(outputPath, '');
      Object.assign(process.env, values, {
        GITHUB_OUTPUT: outputPath,
        DEBZ_DOWNLOAD_CACHE_ROOT: path.join(runnerTemp, phase),
      });
      await runAction(cache);
      const output = await readFile(outputPath, 'utf8');
      assert.match(output, /downloaded-count<<[^\n]+\n0\n/u);
      assert.match(output, /reused-count<<[^\n]+\n0\n/u);
      assert.ok(output.includes(`\n${digest}\n`));
      assert.match(output, new RegExp(`cache-hit<<[^\\n]+\\n${phase === 'exact'}\\n`));
    }
    assert.equal(saves, 1);
    for (const file of transferPaths) {
      await assert.rejects(lstat(path.dirname(file)), { code: 'ENOENT' });
    }
  } finally {
    for (const key of Object.keys(process.env)) {
      if (!(key in previous)) delete process.env[key];
    }
    Object.assign(process.env, previous);
    await rm(root, { recursive: true, force: true });
  }
});

test('native repository and empty closures use real CLI cold, partial, and exact preparation', {
  skip: process.env.DEBZ_DOWNLOAD_INTEGRATION !== '1' ||
    process.env.DEBZ_DOWNLOAD_REPOSITORY_FIXTURE === undefined,
  timeout: 60_000,
}, async () => {
  const executable = process.env.DEBZ_DOWNLOAD_CLI;
  const fixture = process.env.DEBZ_DOWNLOAD_REPOSITORY_FIXTURE;
  assert.ok(executable && path.isAbsolute(executable), 'DEBZ_DOWNLOAD_CLI must be absolute');
  assert.ok(fixture && path.isAbsolute(fixture), 'DEBZ_DOWNLOAD_REPOSITORY_FIXTURE must be absolute');
  const cli = await realpath(executable);
  const temporary = path.resolve(process.cwd(), '../../.tmp');
  await mkdir(temporary, { recursive: true });
  const root = await mkdtemp(path.join(temporary, 'native-download-repository-'));
  const previous = { ...process.env };
  try {
    const workspace = path.join(root, 'workspace');
    const runnerTemp = path.join(root, 'runner');
    await mkdir(workspace);
    await mkdir(runnerTemp);
    const values = environment(workspace, runnerTemp);
    values.DEBZ_DOWNLOAD_TRANSACTION_BACKEND = 'native';
    values.DEBZ_DOWNLOAD_SOURCE = path.join(fixture, 'fixture.sources');
    values.DEBZ_DOWNLOAD_KEYRING = path.join(fixture, 'repository/fixture-keyring.gpg');
    const base: unknown = JSON.parse(await readFile(path.join(fixture, 'base.native.lock.json'), 'utf8'));
    assert.ok(typeof base === 'object' && base !== null && 'target_architecture' in base);
    const architecture = base.target_architecture;
    assert.ok(architecture === 'amd64' || architecture === 'arm64');
    assert.ok('digest_sha256' in base);
    const { digest_sha256, ...closure } = base;
    assert.equal(typeof digest_sha256, 'string');
    const emptyBody = {
      ...closure,
      request_sha256: '1'.repeat(64),
      repositories: [],
      local_artifacts: [],
      packages: [],
    };
    const emptyLock = path.join(workspace, 'empty.native.lock.json');
    await writeFile(emptyLock, JSON.stringify({
      ...emptyBody,
      digest_sha256: createHash('sha256').update(JSON.stringify(emptyBody)).digest('hex'),
    }));
    values.RUNNER_ARCH = architecture === 'arm64' ? 'ARM64' : 'X64';
    values.DEBZ_DOWNLOAD_ARCHITECTURE = architecture;
    values.DEBZ_DOWNLOAD_EXECUTABLE = cli;
    const stored = new Map<string, Buffer>();
    let saves = 0;
    const objectCounts: number[] = [];
    const cache: CacheAdapter = {
      isFeatureAvailable() { return true; },
      async restore(destination, key, prefix) {
        const matched = stored.has(key) ? key : [...stored.keys()].find((candidate) => candidate.startsWith(prefix));
        if (matched === undefined) return undefined;
        const bytes = stored.get(matched);
        assert.ok(bytes !== undefined);
        await writeFile(destination, bytes);
        return matched;
      },
      async save(source, key) {
        assert.match(key, /^debz-package-cas-v2-/u);
        const bytes = await readFile(source);
        const magic = Buffer.from('debz-package-cache-archive-v2\n');
        assert.deepEqual(bytes.subarray(0, magic.length), magic);
        objectCounts.push(bytes.readUInt32BE(magic.length));
        stored.set(key, bytes);
        saves += 1;
      },
    };
    for (const phase of ['cold', 'partial', 'exact', 'empty', 'empty-exact'] as const) {
      const empty = phase.startsWith('empty');
      const exact = phase === 'exact' || phase === 'empty-exact';
      const outputPath = path.join(root, `${phase}.outputs`);
      await writeFile(outputPath, '');
      Object.assign(process.env, values, {
        GITHUB_OUTPUT: outputPath,
        DEBZ_DOWNLOAD_LOCK_INPUT: empty
          ? emptyLock
          : path.join(fixture, `${phase === 'cold' ? 'base' : 'scenario'}.native.lock.json`),
        DEBZ_DOWNLOAD_CACHE_ROOT: path.join(runnerTemp, phase),
        DEBZ_DOWNLOAD_SOURCE: empty ? '' : values.DEBZ_DOWNLOAD_SOURCE,
        DEBZ_DOWNLOAD_KEYRING: empty ? '' : values.DEBZ_DOWNLOAD_KEYRING,
        DEBZ_DOWNLOAD_OFFLINE: String(empty),
      });
      await runAction(cache);
      const output = await readFile(outputPath, 'utf8');
      const downloaded = output.match(/downloaded-count<<[^\n]+\n([0-9]+)\n/u);
      const reused = output.match(/reused-count<<[^\n]+\n([0-9]+)\n/u);
      assert.ok(downloaded !== null && reused !== null);
      assert.equal(Number(downloaded[1]) > 0, !empty && !exact);
      assert.equal(Number(reused[1]) > 0, !empty && phase !== 'cold');
      assert.match(output, new RegExp(`cache-hit<<[^\\n]+\\n${exact}\\n`));
      if (phase !== 'cold') {
        assert.match(output, /cache-matched-key<<[^\n]+\ndebz-package-cas-v2-/u);
      }
    }
    assert.equal(saves, 3);
    assert.deepEqual(objectCounts.map((count) => count > 0), [true, true, false]);
  } finally {
    for (const key of Object.keys(process.env)) {
      if (!(key in previous)) delete process.env[key];
    }
    Object.assign(process.env, previous);
    await rm(root, { recursive: true, force: true });
  }
});
