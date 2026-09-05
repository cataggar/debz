import { execFile as execFileCallback } from 'node:child_process';
import { promisify } from 'node:util';

import { CliDiagnosticError, DownloadActionError } from './errors.js';
import type { Inputs } from './inputs.js';
import { validateDebzVersion } from './inputs.js';

const execFile = promisify(execFileCallback);
const hex64 = /^[0-9a-f]{64}$/;
const cacheKey = /^debz-package-cas-v1-[A-Za-z0-9-]+-[0-9a-f]{64}-[0-9a-f]{64}$/;
const restorePrefix = /^debz-package-cas-v1-[A-Za-z0-9-]+-[0-9a-f]{64}-$/;

export interface CommandRunner {
  run(executable: string, arguments_: string[], timeoutMs: number): Promise<string>;
}

export const systemRunner: CommandRunner = {
  async run(executable, arguments_, timeoutMs) {
    try {
      const result = await execFile(executable, arguments_, {
        encoding: 'utf8',
        env: {
          LANG: 'C',
          LC_ALL: 'C',
        },
        maxBuffer: 2 * 1024 * 1024,
        timeout: timeoutMs,
        windowsHide: true,
      });
      if (result.stderr.length !== 0) {
        throw new DownloadActionError('debz wrote unexpected stderr on success');
      }
      return result.stdout;
    } catch (error) {
      if (error instanceof DownloadActionError) throw error;
      const failure = error as {
        stdout?: string;
        stderr?: string;
        code?: number | string;
        killed?: boolean;
      };
      const diagnostic = parseCliError(failure.stdout);
      if (diagnostic !== undefined) {
        throw new CliDiagnosticError(
          `debz package-cache failed (${diagnostic.id}: ${diagnostic.message})`,
        );
      }
      if (failure.killed) {
        throw new DownloadActionError('debz package-cache exceeded its bounded timeout');
      }
      throw new DownloadActionError(
        `debz command failed with exit code ${String(failure.code ?? 'unknown')}`,
      );
    }
  },
};

export interface FingerprintDocument {
  schema: 'io.github.cataggar.debz.package-cache-fingerprint.v1';
  api_version: 1;
  capability: 'package-cache-v1';
  lock_schema: 'https://debz.dev/schema/exact-closure-lock-v1';
  lock_schema_version: 1;
  lock_digest: string;
  target_architecture: string;
  abi: 'debian-package-archive-v1';
  debz_version: string;
  cas_layout: 'packages-v1';
  payload_policy: 'deb-payload-default-limits-v1';
  origin_mode: 'exact-lock-v1-authenticated-repository';
  acceptance_policy_digest: string;
  fingerprint: string;
  primary_key: string;
  restore_prefix: string;
  cache_root: string;
  cache_path: string;
}

export interface PrepareDocument {
  schema: 'io.github.cataggar.debz.package-cache-result.v1';
  api_version: 1;
  capability: 'package-cache-v1';
  lock_digest: string;
  fingerprint: string;
  target_architecture: string;
  cas_layout: 'packages-v1';
  cache_root: string;
  cache_path: string;
  downloaded_count: number;
  reused_count: number;
  verified_count: number;
  staging: CleanupDocument;
  gc: CleanupDocument & { bytes_deleted: number };
}

export interface RestoredCacheState {
  cacheHit: boolean;
  matchedKey: string;
  kind: 'none' | 'partial' | 'exact';
}

interface CleanupDocument {
  scanned: number;
  deleted: number;
  complete: true;
}

export async function readDebzVersion(
  executable: string,
  runner: CommandRunner = systemRunner,
): Promise<string> {
  let output: string;
  try {
    output = await runner.run(executable, ['version'], 30_000);
  } catch (error) {
    throw new DownloadActionError(
      'installed debz does not provide the required package-cache-v1 version contract',
      { cause: error },
    );
  }
  if (output.includes('\r') || !output.endsWith('\n')) {
    throw new DownloadActionError('debz version output is not one canonical line');
  }
  const value = output.slice(0, -1);
  if (value.includes('\n')) {
    throw new DownloadActionError('debz version output contains multiple lines');
  }
  return validateDebzVersion(value);
}

export async function fingerprintCache(
  executable: string,
  version: string,
  inputs: Inputs,
  runner: CommandRunner = systemRunner,
): Promise<FingerprintDocument> {
  let output: string;
  try {
    output = await runner.run(
      executable,
      ['package-cache', 'fingerprint', ...fingerprintArguments(inputs), '--json'],
      30_000,
    );
  } catch (error) {
    if (error instanceof CliDiagnosticError) throw error;
    throw new DownloadActionError(
      'installed debz does not provide the required package-cache-v1 fingerprint contract',
      { cause: error },
    );
  }
  const document = validateFingerprint(parseJson(output), inputs, version);
  return document;
}

export async function prepareCache(
  executable: string,
  version: string,
  inputs: Inputs,
  expected: FingerprintDocument,
  restored: RestoredCacheState,
  runner: CommandRunner = systemRunner,
): Promise<PrepareDocument> {
  const arguments_ = [
    'package-cache',
    'prepare',
    ...fingerprintArguments(inputs),
    '--lock-wait-ms',
    String(inputs.lockWaitMs),
    '--maximum-repository-records',
    String(inputs.limits.maximumRepositoryRecords),
    '--maximum-staging-entries',
    String(inputs.limits.maximumStagingEntries),
    '--maximum-gc-directory-entries',
    String(inputs.limits.maximumGcDirectoryEntries),
    '--maximum-gc-objects-scanned',
    String(inputs.limits.maximumGcObjectsScanned),
    '--maximum-gc-objects-deleted',
    String(inputs.limits.maximumGcObjectsDeleted),
    '--maximum-gc-bytes-deleted',
    String(inputs.limits.maximumGcBytesDeleted),
    '--restored-cache',
    restored.kind,
  ];
  for (const value of inputs.sources) arguments_.push('--source', value);
  for (const value of inputs.configs) arguments_.push('--config', value);
  for (const value of inputs.keyrings) arguments_.push('--keyring', value);
  if (inputs.defaultRelease !== undefined) {
    arguments_.push('--default-release', inputs.defaultRelease);
  }
  if (inputs.proxy !== undefined) arguments_.push('--proxy', inputs.proxy);
  if (inputs.credentialReference !== undefined) {
    arguments_.push('--credential-reference', inputs.credentialReference);
  }
  if (inputs.offline) arguments_.push('--offline');
  if (inputs.deadlineMs !== undefined) {
    arguments_.push('--deadline-ms', String(inputs.deadlineMs));
  }
  arguments_.push('--json');
  const timeout = Math.min(
    (inputs.deadlineMs ?? 15 * 60_000) + inputs.lockWaitMs + 30_000,
    24 * 60 * 60_000,
  );
  const document = validatePrepare(
    parseJson(await runner.run(executable, arguments_, timeout)),
    inputs,
    expected,
  );
  if (version !== expected.debz_version) {
    throw new DownloadActionError('debz executable changed between action phases');
  }
  return document;
}

export function fingerprintArguments(inputs: Inputs): string[] {
  const arguments_ = [
    '--lock-input',
    inputs.lockInput,
    '--cache-path',
    inputs.cacheRoot,
    '--architecture',
    inputs.architecture,
    '--repository-policy',
    inputs.repositoryPolicy,
    '--maximum-package-bytes',
    String(inputs.limits.maximumPackageBytes),
    '--maximum-total-package-bytes',
    String(inputs.limits.maximumTotalPackageBytes),
    '--maximum-lock-packages',
    String(inputs.limits.maximumLockPackages),
  ];
  for (const value of inputs.foreignArchitectures) {
    arguments_.push('--foreign-architecture', value);
  }
  if (inputs.recommends) arguments_.push('--recommends');
  if (inputs.allowDowngrade) arguments_.push('--allow-downgrade');
  if (inputs.repairCorruptCache) arguments_.push('--repair-corrupt-cache');
  return arguments_;
}

export function validateFingerprint(
  value: unknown,
  inputs: Inputs,
  version: string,
): FingerprintDocument {
  const document = record(value, 'fingerprint');
  exactKeys(document, [
    'schema',
    'api_version',
    'capability',
    'lock_schema',
    'lock_schema_version',
    'lock_digest',
    'target_architecture',
    'abi',
    'debz_version',
    'cas_layout',
    'payload_policy',
    'origin_mode',
    'acceptance_policy_digest',
    'fingerprint',
    'primary_key',
    'restore_prefix',
    'cache_root',
    'cache_path',
  ]);
  literal(document.schema, 'io.github.cataggar.debz.package-cache-fingerprint.v1', 'schema');
  literal(document.api_version, 1, 'api_version');
  literal(document.capability, 'package-cache-v1', 'capability');
  literal(document.lock_schema, 'https://debz.dev/schema/exact-closure-lock-v1', 'lock_schema');
  literal(document.lock_schema_version, 1, 'lock_schema_version');
  literal(document.target_architecture, inputs.architecture, 'target_architecture');
  literal(document.abi, 'debian-package-archive-v1', 'abi');
  literal(document.debz_version, version, 'debz_version');
  literal(document.cas_layout, 'packages-v1', 'cas_layout');
  literal(document.payload_policy, 'deb-payload-default-limits-v1', 'payload_policy');
  literal(document.origin_mode, 'exact-lock-v1-authenticated-repository', 'origin_mode');
  literal(document.cache_root, inputs.cacheRoot, 'cache_root');
  literal(document.cache_path, inputs.cachePath, 'cache_path');
  stringPattern(document.lock_digest, hex64, 'lock_digest');
  stringPattern(document.acceptance_policy_digest, hex64, 'acceptance_policy_digest');
  stringPattern(document.fingerprint, hex64, 'fingerprint');
  stringPattern(document.primary_key, cacheKey, 'primary_key');
  stringPattern(document.restore_prefix, restorePrefix, 'restore_prefix');
  if (!document.primary_key.startsWith(document.restore_prefix)) {
    throw new DownloadActionError('debz primary key is outside its restore prefix');
  }
  return document as unknown as FingerprintDocument;
}

export function validatePrepare(
  value: unknown,
  inputs: Inputs,
  expected: FingerprintDocument,
): PrepareDocument {
  const document = record(value, 'prepare result');
  exactKeys(document, [
    'schema',
    'api_version',
    'capability',
    'lock_digest',
    'fingerprint',
    'target_architecture',
    'cas_layout',
    'cache_root',
    'cache_path',
    'downloaded_count',
    'reused_count',
    'verified_count',
    'staging',
    'gc',
  ]);
  literal(document.schema, 'io.github.cataggar.debz.package-cache-result.v1', 'schema');
  literal(document.api_version, 1, 'api_version');
  literal(document.capability, 'package-cache-v1', 'capability');
  literal(document.lock_digest, expected.lock_digest, 'lock_digest');
  literal(document.fingerprint, expected.fingerprint, 'fingerprint');
  literal(document.target_architecture, inputs.architecture, 'target_architecture');
  literal(document.cas_layout, 'packages-v1', 'cas_layout');
  literal(document.cache_root, inputs.cacheRoot, 'cache_root');
  literal(document.cache_path, inputs.cachePath, 'cache_path');
  const downloaded = count(document.downloaded_count, 'downloaded_count');
  const reused = count(document.reused_count, 'reused_count');
  const verified = count(document.verified_count, 'verified_count');
  if (verified !== downloaded + reused || verified === 0) {
    throw new DownloadActionError('debz prepare result contains inconsistent counts');
  }
  validateCleanup(document.staging, 'staging', false);
  validateCleanup(document.gc, 'gc', true);
  return document as unknown as PrepareDocument;
}

export function restoredCacheState(
  matchedKeyValue: string | undefined,
  inputs: Inputs,
  fingerprint: FingerprintDocument,
): RestoredCacheState {
  if (!inputs.cacheEnabled) {
    return { cacheHit: false, matchedKey: '', kind: 'none' };
  }
  const matchedKey = matchedKeyValue ?? '';
  if (matchedKey.includes('\r') || matchedKey.includes('\n')) {
    throw new DownloadActionError('actions/cache returned a multiline output');
  }
  if (
    matchedKey.length !== 0 &&
    (!cacheKey.test(matchedKey) ||
      (matchedKey !== fingerprint.primary_key &&
        !matchedKey.startsWith(fingerprint.restore_prefix)))
  ) {
    throw new DownloadActionError('actions/cache returned a key outside the CLI-provided restore prefix');
  }
  return {
    cacheHit: matchedKey === fingerprint.primary_key,
    matchedKey,
    kind:
      matchedKey.length === 0
        ? 'none'
        : matchedKey === fingerprint.primary_key
          ? 'exact'
          : 'partial',
  };
}

function parseJson(output: string): unknown {
  if (output.includes('\r') || !output.endsWith('\n')) {
    throw new DownloadActionError('debz JSON output is not canonically newline terminated');
  }
  const body = output.slice(0, -1);
  if (body.includes('\n') || Buffer.byteLength(output) > 1024 * 1024) {
    throw new DownloadActionError('debz JSON output exceeds one bounded line');
  }
  try {
    return JSON.parse(body);
  } catch {
    throw new DownloadActionError('debz returned malformed JSON');
  }
}

function parseCliError(output: string | undefined): { id: string; message: string } | undefined {
  if (output === undefined || output.length > 1024 * 1024) return undefined;
  try {
    const value = JSON.parse(output.trim());
    const document = record(value, 'error');
    if (
      document.schema !== 'io.github.cataggar.debz.package-cache-error.v1' ||
      !Array.isArray(document.diagnostics) ||
      document.diagnostics.length !== 1
    ) {
      return undefined;
    }
    const diagnostic = record(document.diagnostics[0], 'diagnostic');
    if (typeof diagnostic.id !== 'string' || typeof diagnostic.message !== 'string') {
      return undefined;
    }
    if (
      diagnostic.id.includes('\n') ||
      diagnostic.message.includes('\n') ||
      diagnostic.id.length > 128 ||
      diagnostic.message.length > 512
    ) {
      return undefined;
    }
    return { id: diagnostic.id, message: diagnostic.message };
  } catch {
    return undefined;
  }
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new DownloadActionError(`debz ${name} is not an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(document: Record<string, unknown>, expected: string[]): void {
  const actual = Object.keys(document).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new DownloadActionError('debz JSON output has an unsupported field set');
  }
}

function literal<T extends string | number | boolean>(
  value: unknown,
  expected: T,
  name: string,
): asserts value is T {
  if (value !== expected) {
    throw new DownloadActionError(`debz JSON field '${name}' has an unexpected value`);
  }
}

function stringPattern(value: unknown, pattern: RegExp, name: string): asserts value is string {
  if (typeof value !== 'string' || !pattern.test(value) || value.includes('\n')) {
    throw new DownloadActionError(`debz JSON field '${name}' is invalid`);
  }
}

function count(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new DownloadActionError(`debz JSON field '${name}' is not a bounded count`);
  }
  return value as number;
}

function validateCleanup(value: unknown, name: string, includesBytes: boolean): void {
  const document = record(value, name);
  exactKeys(
    document,
    includesBytes
      ? ['scanned', 'deleted', 'bytes_deleted', 'complete']
      : ['scanned', 'deleted', 'complete'],
  );
  count(document.scanned, `${name}.scanned`);
  count(document.deleted, `${name}.deleted`);
  if (includesBytes) count(document.bytes_deleted, `${name}.bytes_deleted`);
  literal(document.complete, true, `${name}.complete`);
}
