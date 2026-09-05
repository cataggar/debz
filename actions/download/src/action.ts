import * as core from '@actions/core';

import {
  createTransferArea,
  defaultCache,
  type CacheAdapter,
} from './cache.js';
import { DownloadActionError, errorMessage } from './errors.js';
import { findDebz, readInputs } from './inputs.js';
import {
  fingerprintCache,
  prepareCache,
  readDebzVersion,
  restoredCacheState,
  captureExecutableIdentity,
  verifyExecutableIdentity,
} from './runner.js';

export async function runMain(cache: CacheAdapter = defaultCache): Promise<void> {
  try {
    requireNode24(process.versions.node);
    await runAction(cache);
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

export async function runAction(cache: CacheAdapter = defaultCache): Promise<void> {
  const inputs = await readInputs();
  delete process.env.DEBZ_DOWNLOAD_PROXY;
  delete process.env['INPUT_PROXY'];
  delete process.env.DEBZ_DOWNLOAD_CREDENTIAL_REFERENCE;
  delete process.env['INPUT_CREDENTIAL-REFERENCE'];
  const executable = await findDebz();
  delete process.env.DEBZ_DOWNLOAD_EXECUTABLE;
  const executableIdentity = await captureExecutableIdentity(executable);
  const version = await readDebzVersion(executable);
  const fingerprint = await fingerprintCache(executable, version, inputs);
  await verifyExecutableIdentity(executableIdentity);
  const cacheAvailable = inputs.cacheEnabled && cache.isFeatureAvailable();
  const transfer = cacheAvailable
    ? await createTransferArea(inputs.runnerTemp)
    : undefined;
  let outputs:
    | {
        cacheHit: boolean;
        matchedKey: string;
        cachePath: string;
        cacheRoot: string;
        lockDigest: string;
        downloadedCount: number;
        reusedCount: number;
      }
    | undefined;
  try {
    const archiveLimit = fingerprint.maximum_archive_bytes;
    const matchedKey =
      cacheAvailable && transfer !== undefined
        ? await cache.restore(
            transfer.restoredArchive,
            fingerprint.primary_key,
            fingerprint.restore_prefix,
            archiveLimit,
          )
        : undefined;
    const restored = restoredCacheState(matchedKey, inputs, fingerprint);
    await verifyExecutableIdentity(executableIdentity);
    const exportArchive =
      cacheAvailable && !restored.cacheHit && transfer !== undefined
        ? transfer.exportArchive
        : undefined;
    const prepared = await prepareCache(
      executable,
      version,
      inputs,
      fingerprint,
      restored,
      {
        input: matchedKey === undefined ? undefined : transfer?.restoredArchive,
        output: exportArchive,
      },
    );
    await verifyExecutableIdentity(executableIdentity);
    if (exportArchive !== undefined) {
      await cache.save(exportArchive, fingerprint.primary_key, archiveLimit);
    }
    await verifyExecutableIdentity(executableIdentity);
    outputs = {
      cacheHit: restored.cacheHit,
      matchedKey: restored.matchedKey,
      cachePath: prepared.cache_path,
      cacheRoot: prepared.cache_root,
      lockDigest: prepared.lock_digest,
      downloadedCount: prepared.downloaded_count,
      reusedCount: prepared.reused_count,
    };
  } finally {
    await transfer?.cleanup();
  }
  if (outputs === undefined) {
    throw new DownloadActionError('download action completed without verified outputs');
  }
  core.setOutput('cache-hit', outputs.cacheHit ? 'true' : 'false');
  core.setOutput('cache-matched-key', outputs.matchedKey);
  core.setOutput('cache-path', outputs.cachePath);
  core.setOutput('cache-root', outputs.cacheRoot);
  core.setOutput('lock-digest', outputs.lockDigest);
  core.setOutput('downloaded-count', String(outputs.downloadedCount));
  core.setOutput('reused-count', String(outputs.reusedCount));
}
