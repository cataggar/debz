import * as core from '@actions/core';

import { defaultCache, type CacheAdapter } from './cache.js';
import { DownloadActionError, errorMessage } from './errors.js';
import { findDebz, readInputs } from './inputs.js';
import {
  fingerprintCache,
  prepareCache,
  readDebzVersion,
  restoredCacheState,
} from './runner.js';

export async function runMain(cache: CacheAdapter = defaultCache): Promise<void> {
  try {
    requireNode24(process.versions.node);
    await run(cache);
  } catch (error) {
    core.setFailed(errorMessage(error));
  }
}

export function requireNode24(version: string): void {
  const major = Number(version.split('.', 1)[0]);
  if (!Number.isInteger(major) || major < 24) {
    throw new DownloadActionError(
      `download action requires the maintained Node 24 runtime, received ${version}`,
    );
  }
}

async function run(cache: CacheAdapter): Promise<void> {
  const inputs = await readInputs();
  delete process.env.DEBZ_DOWNLOAD_PROXY;
  delete process.env['INPUT_PROXY'];
  delete process.env.DEBZ_DOWNLOAD_CREDENTIAL_REFERENCE;
  delete process.env['INPUT_CREDENTIAL-REFERENCE'];
  const executable = await findDebz();
  const version = await readDebzVersion(executable);
  const fingerprint = await fingerprintCache(executable, version, inputs);
  const cacheAvailable = inputs.cacheEnabled && cache.isFeatureAvailable();
  const matchedKey =
    cacheAvailable
      ? await cache.restore(
          fingerprint.cache_path,
          fingerprint.primary_key,
          fingerprint.restore_prefix,
        )
      : undefined;
  const restored = restoredCacheState(matchedKey, inputs, fingerprint);
  const prepared = await prepareCache(
    executable,
    version,
    inputs,
    fingerprint,
    restored,
  );
  if (cacheAvailable && !restored.cacheHit) {
    await cache.save(fingerprint.cache_path, fingerprint.primary_key);
  }

  core.setOutput('cache-hit', restored.cacheHit ? 'true' : 'false');
  core.setOutput('cache-matched-key', restored.matchedKey);
  core.setOutput('cache-path', prepared.cache_path);
  core.setOutput('cache-root', prepared.cache_root);
  core.setOutput('lock-digest', prepared.lock_digest);
  core.setOutput('downloaded-count', String(prepared.downloaded_count));
  core.setOutput('reused-count', String(prepared.reused_count));
}
