import assert from 'node:assert/strict';
import test from 'node:test';

import { cacheKey, parseCacheInput } from '../src/cache.js';
import { clearAmbientConfiguration } from '../src/environment.js';
import { normalizeTrustedSha256 } from '../src/hash.js';
import { normalizePlatform } from '../src/platform.js';
import { resolveVersion } from '../src/version.js';

test('explicit exact version wins over the action ref', () => {
  assert.deepEqual(resolveVersion('v1.2.3-rc.1+build.7', 'deadbeef'), {
    version: '1.2.3-rc.1+build.7',
    tag: 'v1.2.3-rc.1+build.7',
    source: 'input',
  });
  assert.deepEqual(resolveVersion('1.2.3', 'v9.9.9'), {
    version: '1.2.3',
    tag: 'v1.2.3',
    source: 'input',
  });
});

test('an exact semver action ref is coupled to the CLI version', () => {
  assert.deepEqual(resolveVersion('', 'v2.0.0-beta.2+build.9'), {
    version: '2.0.0-beta.2+build.9',
    tag: 'v2.0.0-beta.2+build.9',
    source: 'action-ref',
  });
});

test('ambiguous versions and refs are rejected', () => {
  for (const value of [
    'latest',
    '1.x',
    '^1.2.3',
    'v1',
    'v1.2',
    'v01.2.3',
    'v1.2.3-01',
    ' v1.2.3',
    'v1.2.3 ',
    'vv1.2.3',
  ]) {
    assert.throws(() => resolveVersion(value, ''), /exact SemVer/);
  }
  assert.throws(
    () => resolveVersion(`v1.2.3+${'a'.repeat(129)}`, ''),
    /128-character limit/,
  );
  for (const ref of ['', 'main', 'v1', '0123456789abcdef0123456789abcdef01234567']) {
    assert.throws(() => resolveVersion('', ref), /required|exact (?:v-prefixed )?SemVer/);
  }
});

test('runner platform and process architecture must agree', () => {
  assert.deepEqual(normalizePlatform('Linux', 'X64', 'linux', 'x64'), {
    target: 'linux-x64',
    abi: 'musl-static',
    runnerArch: 'X64',
    processArch: 'x64',
  });
  assert.equal(
    normalizePlatform('Linux', 'ARM64', 'linux', 'arm64').target,
    'linux-arm64',
  );
  assert.throws(() => normalizePlatform('Windows', 'X64', 'win32', 'x64'), /only Linux/);
  assert.throws(() => normalizePlatform('Linux', 'ARM', 'linux', 'arm'), /only X64 and ARM64/);
  assert.throws(() => normalizePlatform('Linux', 'X64', 'linux', 'arm64'), /mismatch/);
});

test('trusted SHA and cache inputs are strict', () => {
  assert.equal(
    normalizeTrustedSha256('A'.repeat(64)),
    'a'.repeat(64),
  );
  for (const value of ['', 'true']) {
    if (value === '') {
      assert.equal(normalizeTrustedSha256(value), undefined);
    } else {
      assert.equal(parseCacheInput(value), true);
    }
  }
  assert.equal(parseCacheInput('false'), false);
  assert.throws(() => parseCacheInput('TRUE'), /exactly/);
  assert.throws(() => normalizeTrustedSha256('a'.repeat(63)), /64 hexadecimal/);
});

test('cache key contains every immutable trust dimension', () => {
  assert.equal(
    cacheKey('linux-arm64', 'v1.2.3', 'a'.repeat(64)),
    `debz-cli-v1-linux-arm64-musl-static-v1.2.3-${'a'.repeat(64)}`,
  );
});

test('ambient proxy and credential configuration is removed', () => {
  const environment: NodeJS.ProcessEnv = {
    HTTP_PROXY: 'http://proxy.invalid',
    https_proxy: 'http://proxy.invalid',
    GH_TOKEN: 'secret',
    GITHUB_TOKEN: 'secret',
    GIT_CONFIG_GLOBAL: '/untrusted/config',
    NPM_CONFIG_USERCONFIG: '/untrusted/npmrc',
    SAFE_VALUE: 'kept',
  };
  clearAmbientConfiguration(environment);
  assert.deepEqual(environment, { SAFE_VALUE: 'kept' });
});
