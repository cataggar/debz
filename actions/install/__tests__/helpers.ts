import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

import type { Inputs, RuntimeEnvironment } from '../src/inputs.js';

export const testRoot = path.resolve(
  process.cwd(),
  '../../.tmp/install-action-tests',
);

export async function createInputEnvironment(
  name: string,
): Promise<{ environment: RuntimeEnvironment; workspace: string; runner: string }> {
  const workspace = path.join(testRoot, name, 'workspace');
  const runner = path.join(testRoot, name, 'runner');
  await mkdir(workspace, { recursive: true });
  await mkdir(runner, { recursive: true });
  await writeFile(path.join(workspace, 'lock.json'), '{}');
  await writeFile(path.join(workspace, 'repo.sources'), 'Types: deb\n');
  await writeFile(path.join(workspace, 'keyring.gpg'), 'keyring');
  return {
    workspace,
    runner,
    environment: {
      GITHUB_WORKSPACE: workspace,
      RUNNER_TEMP: runner,
      GITHUB_ACTION_PATH: path.resolve(process.cwd()),
      RUNNER_OS: 'Linux',
      RUNNER_ARCH: 'X64',
      DEBZ_INSTALL_PACKAGE: 'scenario-main',
      DEBZ_INSTALL_LOCK_INPUT: 'lock.json',
      DEBZ_INSTALL_ARCHITECTURE: 'amd64',
      DEBZ_INSTALL_INSTALL_ROOT: path.join(runner, 'root'),
      DEBZ_INSTALL_STATE_PATH: path.join(runner, 'state'),
      DEBZ_INSTALL_CONFFILE: 'keep-existing',
      DEBZ_INSTALL_ASSUME_YES: 'true',
      DEBZ_INSTALL_NONINTERACTIVE: 'true',
      DEBZ_INSTALL_FORCE: '',
      DEBZ_INSTALL_USE_SUDO: 'false',
      DEBZ_INSTALL_SOURCE: 'repo.sources',
      DEBZ_INSTALL_CONFIG: '',
      DEBZ_INSTALL_KEYRING: 'keyring.gpg',
      DEBZ_INSTALL_FOREIGN_ARCHITECTURE: '',
      DEBZ_INSTALL_DEFAULT_RELEASE: '',
      DEBZ_INSTALL_REPOSITORY_POLICY: 'strict-priority',
      DEBZ_INSTALL_RECOMMENDS: 'false',
      DEBZ_INSTALL_ALLOW_DOWNGRADE: 'false',
      DEBZ_INSTALL_PROXY: '',
      DEBZ_INSTALL_CREDENTIAL_REFERENCE: '',
      DEBZ_INSTALL_DEADLINE_MS: '',
      DEBZ_INSTALL_LOCK_WAIT_MS: '30000',
      DEBZ_INSTALL_MAXIMUM_PACKAGE_BYTES: '1073741824',
      DEBZ_INSTALL_MAXIMUM_TOTAL_PACKAGE_BYTES: '8589934592',
      DEBZ_INSTALL_MAXIMUM_LOCK_PACKAGES: '100000',
      DEBZ_INSTALL_MAXIMUM_REPOSITORY_RECORDS: '1000000',
      DEBZ_INSTALL_MAXIMUM_STAGING_ENTRIES: '100000',
      DEBZ_INSTALL_MAXIMUM_GC_DIRECTORY_ENTRIES: '100000',
      DEBZ_INSTALL_MAXIMUM_GC_OBJECTS_SCANNED: '100000',
      DEBZ_INSTALL_MAXIMUM_GC_OBJECTS_DELETED: '100000',
      DEBZ_INSTALL_MAXIMUM_GC_BYTES_DELETED: '8589934592',
      DEBZ_INSTALL_CACHE: 'true',
      DEBZ_INSTALL_CACHE_ROOT: path.join(runner, 'cache'),
      DEBZ_INSTALL_OFFLINE: 'false',
      DEBZ_INSTALL_CACHE_ONLY: 'false',
      DEBZ_INSTALL_REPAIR_CORRUPT_CACHE: 'false',
      DEBZ_INSTALL_DEBZ_VERSION: 'v0.3.0',
      DEBZ_INSTALL_SHA256: '',
      DEBZ_INSTALL_TOKEN: '',
      DEBZ_INSTALL_CLI_CACHE: 'true',
    },
  };
}

export function fixtureInputs(root: string): Inputs {
  return {
    workspace: path.join(root, 'workspace'),
    runnerTemp: path.join(root, 'runner'),
    actionPath: path.join(root, 'actions', 'install'),
    package: 'scenario-main',
    lockInput: path.join(root, 'workspace', 'lock.json'),
    architecture: 'amd64',
    target: 'linux-x64',
    installRoot: path.join(root, 'runner', 'root'),
    statePath: path.join(root, 'runner', 'state'),
    conffile: 'keep-existing',
    forces: ['depends', 'overwrite'],
    useSudo: false,
    sources: [path.join(root, 'workspace', 'repo.sources')],
    configs: [],
    keyrings: [path.join(root, 'workspace', 'keyring.gpg')],
    foreignArchitectures: [],
    repositoryPolicy: 'strict-priority',
    recommends: false,
    allowDowngrade: false,
    lockWaitMs: 30000,
    limits: {
      maximumPackageBytes: 1073741824,
      maximumTotalPackageBytes: 8589934592,
      maximumLockPackages: 100000,
      maximumRepositoryRecords: 1000000,
      maximumStagingEntries: 100000,
      maximumGcDirectoryEntries: 100000,
      maximumGcObjectsScanned: 100000,
      maximumGcObjectsDeleted: 100000,
      maximumGcBytesDeleted: 8589934592,
    },
    packageCacheEnabled: true,
    cacheRoot: path.join(root, 'runner', 'cache'),
    cachePath: path.join(root, 'runner', 'cache', 'packages-v1', 'objects'),
    offline: false,
    repairCorruptCache: false,
    debzVersion: 'v0.3.0',
    cliCacheEnabled: true,
  };
}

export function commandResult(exitStatus = 0): string {
  return `${JSON.stringify({
    schema: 'io.github.cataggar.debz.command.v1',
    api_version: 1,
    operation: 'install',
    exit_status: exitStatus,
    changed: true,
    summary: exitStatus === 0 ? 'transaction completed' : 'transaction failed',
    items: [],
    diagnostics:
      exitStatus === 0
        ? []
        : [{ id: 'transaction_failed', message: 'fixture failure' }],
  })}\n`;
}

export function transactionSummary(lockDigest = 'a'.repeat(64)): string {
  return `${JSON.stringify({
    schema: 'io.github.cataggar.debz.transaction-result-summary.v1',
    api_version: 1,
    transaction_schema: 'https://debz.dev/schema/transaction-result-v1',
    transaction_schema_version: 1,
    target_architecture: 'amd64',
    request_sha256: 'b'.repeat(64),
    solver_policy_sha256: 'c'.repeat(64),
    lock_sha256: lockDigest,
    transaction_digest_sha256: 'd'.repeat(64),
    package_count: 4,
    outcome: 'succeeded',
    final_verification_status: 'exact_match',
    lock_evidence: 'exact_match',
  })}\n`;
}
