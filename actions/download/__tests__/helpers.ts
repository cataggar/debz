import type { Inputs, RuntimeEnvironment } from '../src/inputs.js';
import type {
  FingerprintDocument,
  PrepareDocument,
} from '../src/runner.js';

export function environment(
  workspace: string,
  runnerTemp: string,
): RuntimeEnvironment {
  return {
    GITHUB_WORKSPACE: workspace,
    RUNNER_TEMP: runnerTemp,
    RUNNER_OS: 'Linux',
    RUNNER_ARCH: 'X64',
    DEBZ_DOWNLOAD_LOCK_INPUT: 'lock.json',
    DEBZ_DOWNLOAD_ARCHITECTURE: 'amd64',
    DEBZ_DOWNLOAD_SOURCE: 'repo.sources',
    DEBZ_DOWNLOAD_CONFIG: '',
    DEBZ_DOWNLOAD_KEYRING: 'keyring.gpg',
    DEBZ_DOWNLOAD_FOREIGN_ARCHITECTURE: '',
    DEBZ_DOWNLOAD_DEFAULT_RELEASE: '',
    DEBZ_DOWNLOAD_REPOSITORY_POLICY: 'strict-priority',
    DEBZ_DOWNLOAD_RECOMMENDS: 'false',
    DEBZ_DOWNLOAD_ALLOW_DOWNGRADE: 'false',
    DEBZ_DOWNLOAD_PROXY: '',
    DEBZ_DOWNLOAD_CREDENTIAL_REFERENCE: '',
    DEBZ_DOWNLOAD_DEADLINE_MS: '',
    DEBZ_DOWNLOAD_LOCK_WAIT_MS: '30000',
    DEBZ_DOWNLOAD_MAXIMUM_PACKAGE_BYTES: '1073741824',
    DEBZ_DOWNLOAD_MAXIMUM_TOTAL_PACKAGE_BYTES: '8589934592',
    DEBZ_DOWNLOAD_MAXIMUM_LOCK_PACKAGES: '100000',
    DEBZ_DOWNLOAD_MAXIMUM_REPOSITORY_RECORDS: '1000000',
    DEBZ_DOWNLOAD_MAXIMUM_STAGING_ENTRIES: '100000',
    DEBZ_DOWNLOAD_MAXIMUM_GC_DIRECTORY_ENTRIES: '100000',
    DEBZ_DOWNLOAD_MAXIMUM_GC_OBJECTS_SCANNED: '100000',
    DEBZ_DOWNLOAD_MAXIMUM_GC_OBJECTS_DELETED: '100000',
    DEBZ_DOWNLOAD_MAXIMUM_GC_BYTES_DELETED: '8589934592',
    DEBZ_DOWNLOAD_CACHE: 'true',
    DEBZ_DOWNLOAD_CACHE_ROOT: '',
    DEBZ_DOWNLOAD_OFFLINE: 'false',
    DEBZ_DOWNLOAD_CACHE_ONLY: 'false',
    DEBZ_DOWNLOAD_REPAIR_CORRUPT_CACHE: 'false',
  };
}

export function fingerprint(inputs: Inputs): FingerprintDocument {
  const policy = 'a'.repeat(64);
  const lock = 'b'.repeat(64);
  return {
    schema: 'io.github.cataggar.debz.package-cache-fingerprint.v1',
    api_version: 1,
    capability: 'package-cache-v1',
    lock_schema: 'https://debz.dev/schema/exact-closure-lock-v1',
    lock_schema_version: 1,
    lock_digest: lock,
    target_architecture: inputs.architecture,
    abi: 'debian-package-archive-v1',
    debz_version: '0.3.0',
    cas_layout: 'packages-v1',
    payload_policy: 'deb-payload-default-limits-v1',
    origin_mode: 'exact-lock-v1-authenticated-repository',
    acceptance_policy_digest: policy,
    fingerprint: 'c'.repeat(64),
    primary_key: `debz-package-cas-v1-amd64-${policy}-${lock}`,
    restore_prefix: `debz-package-cas-v1-amd64-${policy}-`,
    cache_root: inputs.cacheRoot,
    cache_path: inputs.cachePath,
  };
}

export function preparation(
  inputs: Inputs,
  expected: FingerprintDocument,
): PrepareDocument {
  return {
    schema: 'io.github.cataggar.debz.package-cache-result.v1',
    api_version: 1,
    capability: 'package-cache-v1',
    lock_digest: expected.lock_digest,
    fingerprint: expected.fingerprint,
    target_architecture: inputs.architecture,
    cas_layout: 'packages-v1',
    cache_root: inputs.cacheRoot,
    cache_path: inputs.cachePath,
    downloaded_count: 1,
    reused_count: 2,
    verified_count: 3,
    staging: { scanned: 0, deleted: 0, complete: true },
    gc: { scanned: 3, deleted: 1, bytes_deleted: 4, complete: true },
  };
}
