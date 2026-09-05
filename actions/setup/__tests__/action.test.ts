import assert from 'node:assert/strict';
import { mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { setup, type ActionIO, type ReleaseClient, type SetupServices } from '../src/action.js';
import { cacheKey, type CacheAdapter } from '../src/cache.js';
import { sha256Bytes } from '../src/hash.js';
import { makeArchive, releaseMetadata } from './helpers.js';

const testRoot = path.resolve(process.cwd(), '../../.tmp/setup-action-tests/action');
const archiveRoot = 'debz-1.2.3-linux-x64';
const archive = makeArchive(archiveRoot);
const digest = sha256Bytes(archive);

test.before(async () => {
  await rm(testRoot, { recursive: true, force: true });
  await mkdir(testRoot, { recursive: true });
});

test.after(async () => {
  await rm(testRoot, { recursive: true, force: true });
});

function runtime(runnerTemp: string) {
  return {
    actionRef: '0123456789abcdef0123456789abcdef01234567',
    runnerOS: 'Linux',
    runnerArch: 'X64',
    runnerTemp,
    githubServerURL: 'https://github.com',
    githubAPIURL: 'https://api.github.com',
    processPlatform: 'linux' as const,
    processArch: 'x64' as const,
  };
}

function captureIO(): {
  io: ActionIO;
  outputs: Record<string, string>;
  paths: string[];
  states: Record<string, string>;
  messages: string[];
} {
  const outputs: Record<string, string> = {};
  const paths: string[] = [];
  const states: Record<string, string> = {};
  const messages: string[] = [];
  return {
    outputs,
    paths,
    states,
    messages,
    io: {
      addPath: (value) => paths.push(value),
      info: (value) => messages.push(value),
      warning: (value) => messages.push(value),
      setOutput: (name, value) => {
        outputs[name] = value;
      },
      saveState: (name, value) => {
        states[name] = value;
      },
    },
  };
}

function releaseClient(overrides: Partial<ReleaseClient> = {}): ReleaseClient {
  return {
    getRelease: async () => releaseMetadata(digest, archive.length),
    resolveTagCommit: async () => 'b'.repeat(40),
    getAttestationBundles: async () => [{ bundle: true }],
    downloadAsset: async () => archive,
    ...overrides,
  };
}

function noCache(): CacheAdapter {
  return {
    isFeatureAvailable: () => false,
    restoreCache: async () => {
      throw new Error('unexpected restore');
    },
    saveCache: async () => {
      throw new Error('unexpected save');
    },
  };
}

function services(
  client: ReleaseClient,
  overrides: Partial<SetupServices> = {},
): SetupServices {
  return {
    createReleaseClient: () => client,
    verifyProvenance: async () => {},
    cache: noCache(),
    verifyVersion: async () => {},
    ...overrides,
  };
}

test('trusted SHA mode installs exactly and publishes stable outputs last', async () => {
  const runnerTemp = path.join(testRoot, 'sha-success');
  await mkdir(runnerTemp, { recursive: true });
  let provenanceCalled = false;
  const captured = captureIO();
  const result = await setup(
    {
      debzVersion: 'v1.2.3',
      sha256: digest.toUpperCase(),
      token: '',
      cache: 'false',
    },
    runtime(runnerTemp),
    captured.io,
    services(releaseClient(), {
      verifyProvenance: async () => {
        provenanceCalled = true;
      },
    }),
  );
  assert.equal(provenanceCalled, false);
  assert.equal(result.cacheHit, false);
  assert.deepEqual(captured.outputs, {
    'debz-path': result.executablePath,
    'debz-version': 'v1.2.3',
    target: 'linux-x64',
    'cache-hit': 'false',
  });
  assert.deepEqual(captured.paths, [path.dirname(result.executablePath)]);
});

test('provenance mode resolves the tag commit and validates before download', async () => {
  const runnerTemp = path.join(testRoot, 'provenance-success');
  await mkdir(runnerTemp, { recursive: true });
  const events: string[] = [];
  const client = releaseClient({
    resolveTagCommit: async () => {
      events.push('commit');
      return 'b'.repeat(40);
    },
    getAttestationBundles: async () => {
      events.push('attestations');
      return [{ bundle: true }];
    },
    downloadAsset: async () => {
      events.push('download');
      return archive;
    },
  });
  const captured = captureIO();
  await setup(
    { debzVersion: '1.2.3', sha256: '', token: '', cache: 'false' },
    runtime(runnerTemp),
    captured.io,
    services(client, {
      verifyProvenance: async (_bundles, expected) => {
        events.push('verify');
        assert.equal(expected.commit, 'b'.repeat(40));
        assert.equal(expected.digest, digest);
      },
    }),
  );
  assert.ok(events.indexOf('verify') < events.indexOf('download'));
  assert.deepEqual(new Set(events.slice(0, 2)), new Set(['commit', 'attestations']));
});

test('a trusted SHA mismatch fails before download and emits no outputs', async () => {
  let downloaded = false;
  const captured = captureIO();
  await assert.rejects(
    setup(
      {
        debzVersion: 'v1.2.3',
        sha256: '0'.repeat(64),
        token: '',
        cache: 'false',
      },
      runtime(path.join(testRoot, 'sha-mismatch')),
      captured.io,
      services(
        releaseClient({
          downloadAsset: async () => {
            downloaded = true;
            return archive;
          },
        }),
      ),
    ),
    /does not match GitHub's asset digest/,
  );
  assert.equal(downloaded, false);
  assert.deepEqual(captured.outputs, {});
  assert.deepEqual(captured.paths, []);
});

test('version mismatch emits no success-shaped path or outputs', async () => {
  const captured = captureIO();
  await assert.rejects(
    setup(
      {
        debzVersion: 'v1.2.3',
        sha256: digest,
        token: '',
        cache: 'false',
      },
      runtime(path.join(testRoot, 'version-mismatch')),
      captured.io,
      services(releaseClient(), {
        verifyVersion: async () => {
          throw new Error('wrong version');
        },
      }),
    ),
    /wrong version/,
  );
  assert.deepEqual(captured.outputs, {});
  assert.deepEqual(captured.paths, []);
});

test('an exact cache hit is reverified and skips download', async () => {
  const runnerTemp = path.join(testRoot, 'cache-hit');
  let downloaded = false;
  const adapter: CacheAdapter = {
    isFeatureAvailable: () => true,
    restoreCache: async (key, expectedSize) => {
      assert.equal(key, cacheKey('linux-x64', 'v1.2.3', digest));
      assert.equal(expectedSize, archive.length);
      return archive;
    },
    saveCache: async () => 1,
  };
  const captured = captureIO();
  const result = await setup(
    {
      debzVersion: 'v1.2.3',
      sha256: digest,
      token: '',
      cache: 'true',
    },
    runtime(runnerTemp),
    captured.io,
    services(
      releaseClient({
        downloadAsset: async () => {
          downloaded = true;
          return archive;
        },
      }),
      { cache: adapter },
    ),
  );
  assert.equal(downloaded, false);
  assert.equal(result.cacheHit, true);
  assert.equal(captured.outputs['cache-hit'], 'true');
  assert.deepEqual(captured.states, {});
});

test('a tampered exact cache hit fails and never downloads around corruption', async () => {
  const runnerTemp = path.join(testRoot, 'cache-corrupt');
  let downloaded = false;
  const adapter: CacheAdapter = {
    isFeatureAvailable: () => true,
    restoreCache: async () => {
      const tampered = Buffer.from(archive);
      tampered[tampered.length - 1] ^= 0xff;
      return tampered;
    },
    saveCache: async () => 1,
  };
  const captured = captureIO();
  await assert.rejects(
    setup(
      {
        debzVersion: 'v1.2.3',
        sha256: digest,
        token: '',
        cache: 'true',
      },
      runtime(runnerTemp),
      captured.io,
      services(
        releaseClient({
          downloadAsset: async () => {
            downloaded = true;
            return archive;
          },
        }),
        { cache: adapter },
      ),
    ),
    /SHA-256 mismatch/,
  );
  assert.equal(downloaded, false);
  assert.deepEqual(captured.outputs, {});
});

test('an optional cache transport failure falls back to the verified release download', async () => {
  const runnerTemp = path.join(testRoot, 'cache-unavailable');
  let downloaded = false;
  const adapter: CacheAdapter = {
    isFeatureAvailable: () => true,
    restoreCache: async () => {
      throw new Error('cache service unavailable');
    },
    saveCache: async () => 1,
  };
  const captured = captureIO();
  const result = await setup(
    {
      debzVersion: 'v1.2.3',
      sha256: digest,
      token: '',
      cache: 'true',
    },
    runtime(runnerTemp),
    captured.io,
    services(
      releaseClient({
        downloadAsset: async () => {
          downloaded = true;
          return archive;
        },
      }),
      { cache: adapter },
    ),
  );
  assert.equal(downloaded, true);
  assert.equal(result.cacheHit, false);
  assert.ok(captured.messages.some((message) => message.includes('cache service unavailable')));
});

test('only a newly verified cache miss schedules an exact post save', async () => {
  const runnerTemp = path.join(testRoot, 'cache-save');
  const adapter: CacheAdapter = {
    isFeatureAvailable: () => true,
    restoreCache: async () => undefined,
    saveCache: async () => 1,
  };
  const captured = captureIO();
  await setup(
    {
      debzVersion: 'v1.2.3',
      sha256: digest,
      token: '',
      cache: 'true',
    },
    runtime(runnerTemp),
    captured.io,
    services(releaseClient(), { cache: adapter }),
  );
  assert.equal(captured.states['debz-cache-key'], cacheKey('linux-x64', 'v1.2.3', digest));
  assert.equal(captured.states['debz-cache-archive-digest'], digest);
  assert.equal(captured.states['debz-cache-expected-root'], archiveRoot);
  assert.equal(captured.states['debz-cache-asset-size'], String(archive.length));
});
