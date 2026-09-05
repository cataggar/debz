import * as core from '@actions/core';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

import {
  STATE_ARCHIVE_DIGEST,
  STATE_ASSET_SIZE,
  STATE_CACHE_KEY,
  STATE_CACHE_PATH,
  STATE_EXPECTED_ROOT,
  STATE_VERSION,
  defaultCacheAdapter,
} from './cache.js';
import { configureDirectNetwork } from './environment.js';
import { errorMessage } from './errors.js';
import { SHA256_PATTERN, sha256Bytes } from './hash.js';
import { CACHED_ARCHIVE_NAME, verifyCachedInstallation } from './archive.js';
import { verifyExecutableVersion } from './runner.js';

async function runPost(): Promise<void> {
  delete process.env.INPUT_TOKEN;
  const cachePath = core.getState(STATE_CACHE_PATH);
  if (!cachePath) {
    return;
  }
  try {
    configureDirectNetwork();
    const key = core.getState(STATE_CACHE_KEY);
    const expectedRoot = core.getState(STATE_EXPECTED_ROOT);
    const digest = core.getState(STATE_ARCHIVE_DIGEST);
    const version = core.getState(STATE_VERSION);
    const sizeText = core.getState(STATE_ASSET_SIZE);
    const size = Number(sizeText);
    if (
      !key ||
      !expectedRoot ||
      !version ||
      !SHA256_PATTERN.test(digest) ||
      !Number.isSafeInteger(size) ||
      size <= 0
    ) {
      throw new Error('cache save state is incomplete or malformed');
    }
    const verified = await verifyCachedInstallation(cachePath, expectedRoot, size, digest);
    await verifyExecutableVersion(verified.executablePath, version);
    if (!defaultCacheAdapter.isFeatureAvailable()) {
      core.warning('GitHub cache service is unavailable; verified debz installation was not cached');
      return;
    }
    try {
      const archive = await readFile(path.join(cachePath, CACHED_ARCHIVE_NAME));
      if (archive.length !== size || sha256Bytes(archive) !== digest) {
        throw new Error('release archive changed after post-action verification');
      }
      const cacheID = await defaultCacheAdapter.saveCache(key, archive);
      if (cacheID < 0) {
        core.info('Runner cache policy does not permit saving the verified debz installation');
      } else {
        core.info(`Saved verified debz CLI cache ${key}`);
      }
    } catch (error) {
      core.warning(`Could not save the optional debz CLI cache: ${errorMessage(error)}`);
    }
  } catch (error) {
    core.setFailed(`Refusing to cache an unverified debz installation: ${errorMessage(error)}`);
  }
}

await runPost();
