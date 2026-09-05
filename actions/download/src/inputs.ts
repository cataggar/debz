import {
  access,
  lstat,
  mkdir,
  realpath,
  stat,
} from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';

import { DownloadActionError } from './errors.js';

const INPUT_PREFIX = 'DEBZ_DOWNLOAD_';
const architecturePattern = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;
const semverPattern =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export interface Limits {
  maximumPackageBytes: number;
  maximumTotalPackageBytes: number;
  maximumLockPackages: number;
  maximumRepositoryRecords: number;
  maximumStagingEntries: number;
  maximumGcDirectoryEntries: number;
  maximumGcObjectsScanned: number;
  maximumGcObjectsDeleted: number;
  maximumGcBytesDeleted: number;
}

export interface Inputs {
  lockInput: string;
  architecture: string;
  sources: string[];
  configs: string[];
  keyrings: string[];
  foreignArchitectures: string[];
  defaultRelease?: string;
  repositoryPolicy: 'strict-priority' | 'best-version';
  recommends: boolean;
  allowDowngrade: boolean;
  proxy?: string;
  credentialReference?: string;
  deadlineMs?: number;
  lockWaitMs: number;
  limits: Limits;
  cacheEnabled: boolean;
  cacheRoot: string;
  cachePath: string;
  offline: boolean;
  repairCorruptCache: boolean;
}

export interface RuntimeEnvironment {
  [key: string]: string | undefined;
}

export async function readInputs(
  environment: RuntimeEnvironment = process.env,
  runtime: { platform: NodeJS.Platform; architecture: string } = {
    platform: process.platform,
    architecture: process.arch,
  },
): Promise<Inputs> {
  validateRunner(environment, runtime);
  const workspace = requiredEnvironmentPath(environment, 'GITHUB_WORKSPACE');
  const runnerTemp = requiredEnvironmentPath(environment, 'RUNNER_TEMP');
  const lockInput = await resolveRegularFile(
    scalar(environment, 'LOCK_INPUT', true),
    workspace,
    'lock-input',
  );
  const sources = await resolveFileList(
    multiline(environment, 'SOURCE'),
    workspace,
    'source',
  );
  const configs = await resolveFileList(
    multiline(environment, 'CONFIG'),
    workspace,
    'config',
  );
  if (sources.length === 0 && configs.length === 0) {
    throw new DownloadActionError(
      "one or more explicit 'source' or 'config' paths are required",
    );
  }
  const keyrings = await resolveFileList(
    multiline(environment, 'KEYRING', true),
    workspace,
    'keyring',
  );
  if (keyrings.length === 0) {
    throw new DownloadActionError("one or more explicit 'keyring' paths are required");
  }

  const architecture = scalar(environment, 'ARCHITECTURE', true);
  if (architecture !== 'amd64' && architecture !== 'arm64') {
    throw new DownloadActionError(`invalid target architecture '${architecture}'`);
  }
  const foreignArchitectures = lineList(
    multiline(environment, 'FOREIGN_ARCHITECTURE'),
    'foreign-architecture',
  );
  if (foreignArchitectures.length > 16) {
    throw new DownloadActionError('foreign-architecture exceeds 16 entries');
  }
  for (const foreign of foreignArchitectures) {
    if (
      !architecturePattern.test(foreign) ||
      (foreign !== 'amd64' && foreign !== 'arm64') ||
      foreign === architecture
    ) {
      throw new DownloadActionError(`invalid foreign architecture '${foreign}'`);
    }
  }

  const repositoryPolicy = scalar(environment, 'REPOSITORY_POLICY', true);
  if (repositoryPolicy !== 'strict-priority' && repositoryPolicy !== 'best-version') {
    throw new DownloadActionError(
      "repository-policy must be 'strict-priority' or 'best-version'",
    );
  }
  const cacheEnabled = booleanInput(environment, 'CACHE');
  const offline =
    booleanInput(environment, 'OFFLINE') ||
    booleanInput(environment, 'CACHE_ONLY');
  const repairCorruptCache = booleanInput(environment, 'REPAIR_CORRUPT_CACHE');
  if (offline && repairCorruptCache) {
    throw new DownloadActionError(
      'repair-corrupt-cache cannot be enabled with offline/cache-only mode',
    );
  }
  const recommends = booleanInput(environment, 'RECOMMENDS');
  const allowDowngrade = booleanInput(environment, 'ALLOW_DOWNGRADE');
  const deadlineMs = optionalPositiveInteger(environment, 'DEADLINE_MS', 86_400_000);
  const lockWaitMs = positiveInteger(environment, 'LOCK_WAIT_MS', 300_000);
  const limits: Limits = {
    maximumPackageBytes: positiveInteger(
      environment,
      'MAXIMUM_PACKAGE_BYTES',
      4 * 1024 * 1024 * 1024,
    ),
    maximumTotalPackageBytes: positiveInteger(
      environment,
      'MAXIMUM_TOTAL_PACKAGE_BYTES',
      10 * 1024 * 1024 * 1024,
    ),
    maximumLockPackages: positiveInteger(
      environment,
      'MAXIMUM_LOCK_PACKAGES',
      1_000_000,
    ),
    maximumRepositoryRecords: positiveInteger(
      environment,
      'MAXIMUM_REPOSITORY_RECORDS',
      5_000_000,
    ),
    maximumStagingEntries: positiveInteger(
      environment,
      'MAXIMUM_STAGING_ENTRIES',
      1_000_000,
    ),
    maximumGcDirectoryEntries: positiveInteger(
      environment,
      'MAXIMUM_GC_DIRECTORY_ENTRIES',
      1_000_000,
    ),
    maximumGcObjectsScanned: positiveInteger(
      environment,
      'MAXIMUM_GC_OBJECTS_SCANNED',
      1_000_000,
    ),
    maximumGcObjectsDeleted: positiveInteger(
      environment,
      'MAXIMUM_GC_OBJECTS_DELETED',
      1_000_000,
    ),
    maximumGcBytesDeleted: positiveInteger(
      environment,
      'MAXIMUM_GC_BYTES_DELETED',
      10 * 1024 * 1024 * 1024,
    ),
  };
  const defaultRelease = optionalScalar(environment, 'DEFAULT_RELEASE');
  if (defaultRelease !== undefined && !/^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$/.test(defaultRelease)) {
    throw new DownloadActionError('default-release has an invalid spelling');
  }
  const proxy = optionalScalar(environment, 'PROXY');
  if (proxy !== undefined) {
    let parsed: URL;
    try {
      parsed = new URL(proxy);
    } catch {
      throw new DownloadActionError('proxy must be an absolute HTTP(S) URI');
    }
    if (
      (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
      parsed.username.length !== 0 ||
      parsed.password.length !== 0 ||
      parsed.search.length !== 0 ||
      parsed.hash.length !== 0
    ) {
      throw new DownloadActionError(
        'proxy must be an HTTP(S) origin without credentials, query, or fragment',
      );
    }
  }
  const credentialValue = scalar(environment, 'CREDENTIAL_REFERENCE');
  const credentialReference =
    credentialValue.length === 0
      ? undefined
      : await resolveRegularFile(
          credentialValue,
          workspace,
          'credential-reference',
        );

  const cacheRoot = await resolveCacheRoot(
    scalar(environment, 'CACHE_ROOT'),
    runnerTemp,
  );
  const cachePath = path.join(cacheRoot, 'packages-v1', 'objects');
  await createSafeDirectory(cachePath, runnerTemp);

  const protectedPaths = [
    lockInput,
    ...sources,
    ...configs,
    ...keyrings,
    ...(credentialReference === undefined ? [] : [credentialReference]),
  ];
  for (const protectedPath of protectedPaths) {
    if (isWithin(cacheRoot, protectedPath)) {
      throw new DownloadActionError(
        'lock, repository, keyring, and credential files must be outside cache-root',
      );
    }
  }

  return {
    lockInput,
    architecture,
    sources,
    configs,
    keyrings,
    foreignArchitectures,
    defaultRelease,
    repositoryPolicy,
    recommends,
    allowDowngrade,
    proxy,
    credentialReference,
    deadlineMs,
    lockWaitMs,
    limits,
    cacheEnabled,
    cacheRoot,
    cachePath,
    offline,
    repairCorruptCache,
  };
}

function validateRunner(
  environment: RuntimeEnvironment,
  runtime: { platform: NodeJS.Platform; architecture: string },
): void {
  const runnerOs = environment.RUNNER_OS ?? '';
  const runnerArchitecture = environment.RUNNER_ARCH ?? '';
  const valid =
    runnerOs === 'Linux' &&
    runtime.platform === 'linux' &&
    ((runnerArchitecture === 'X64' && runtime.architecture === 'x64') ||
      (runnerArchitecture === 'ARM64' && runtime.architecture === 'arm64'));
  if (!valid) {
    throw new DownloadActionError(
      `unsupported runner ${runnerOs || 'unknown'}/${runnerArchitecture || 'unknown'} (${runtime.platform}/${runtime.architecture})`,
    );
  }
}

export async function findDebz(
  environment: RuntimeEnvironment = process.env,
): Promise<string> {
  const pathValue = environment.PATH ?? '';
  for (const entry of pathValue.split(path.delimiter)) {
    if (entry.length === 0 || !path.isAbsolute(entry)) continue;
    const candidate = path.join(entry, 'debz');
    try {
      const candidateStat = await stat(candidate);
      if (!candidateStat.isFile()) continue;
      await access(candidate, fsConstants.X_OK);
      const resolved = await realpath(candidate);
      if (resolved !== path.resolve(candidate)) continue;
      return resolved;
    } catch {
      // Continue searching explicit absolute PATH entries.
    }
  }
  throw new DownloadActionError(
    "debz was not found as a regular executable on PATH; run cataggar/debz/actions/setup first",
  );
}

export function validateDebzVersion(value: string): string {
  if (!semverPattern.test(value)) {
    throw new DownloadActionError(
      'debz version returned unsupported non-SemVer output',
    );
  }
  return value;
}

function scalar(
  environment: RuntimeEnvironment,
  name: string,
  required = false,
): string {
  const value = inputValue(environment, name);
  if (value.includes('\0') || value.includes('\r') || value.includes('\n')) {
    throw new DownloadActionError(`${inputName(name)} must be a single-line value`);
  }
  const trimmed = value.trim();
  if (required && trimmed.length === 0) {
    throw new DownloadActionError(`${inputName(name)} is required`);
  }
  return trimmed;
}

function optionalScalar(
  environment: RuntimeEnvironment,
  name: string,
): string | undefined {
  const value = scalar(environment, name);
  return value.length === 0 ? undefined : value;
}

function multiline(
  environment: RuntimeEnvironment,
  name: string,
  required = false,
): string {
  const value = inputValue(environment, name);
  if (value.includes('\0')) {
    throw new DownloadActionError(`${inputName(name)} contains a NUL byte`);
  }
  const trimmed = value.trim();
  if (required && trimmed.length === 0) {
    throw new DownloadActionError(`${inputName(name)} is required`);
  }
  return trimmed;
}

function booleanInput(environment: RuntimeEnvironment, name: string): boolean {
  const value = scalar(environment, name, true);
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new DownloadActionError(`${inputName(name)} must be exactly 'true' or 'false'`);
}

function positiveInteger(
  environment: RuntimeEnvironment,
  name: string,
  maximum: number,
): number {
  const value = scalar(environment, name, true);
  if (!/^[1-9]\d*$/.test(value)) {
    throw new DownloadActionError(`${inputName(name)} must be a positive integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) {
    throw new DownloadActionError(
      `${inputName(name)} exceeds its bounded maximum of ${maximum}`,
    );
  }
  return parsed;
}

function optionalPositiveInteger(
  environment: RuntimeEnvironment,
  name: string,
  maximum: number,
): number | undefined {
  if (scalar(environment, name).length === 0) return undefined;
  return positiveInteger(environment, name, maximum);
}

function lineList(value: string, name: string): string[] {
  if (value.length === 0) return [];
  const entries = value.split(/\r?\n/u).map((entry) => entry.trim());
  if (entries.some((entry) => entry.length === 0 || entry.includes('\0'))) {
    throw new DownloadActionError(`${name} contains an empty or invalid line`);
  }
  if (new Set(entries).size !== entries.length) {
    throw new DownloadActionError(`${name} contains a duplicate entry`);
  }
  return entries;
}

async function resolveFileList(
  value: string,
  workspace: string,
  name: string,
): Promise<string[]> {
  const resolved: string[] = [];
  for (const entry of lineList(value, name)) {
    resolved.push(await resolveRegularFile(entry, workspace, name));
  }
  if (new Set(resolved).size !== resolved.length) {
    throw new DownloadActionError(`${name} resolves to a duplicate path`);
  }
  return resolved;
}

async function resolveRegularFile(
  value: string,
  workspace: string,
  name: string,
): Promise<string> {
  rejectAmbiguousComponents(value, name);
  const candidate = path.isAbsolute(value)
    ? path.resolve(value)
    : path.resolve(workspace, value);
  if (!path.isAbsolute(value) && !isWithin(workspace, candidate)) {
    throw new DownloadActionError(`${name} escapes GITHUB_WORKSPACE`);
  }
  let resolved: string;
  try {
    resolved = await realpath(candidate);
  } catch {
    throw new DownloadActionError(`${name} does not exist`);
  }
  if (resolved !== candidate) {
    throw new DownloadActionError(`${name} must not traverse a symbolic link`);
  }
  const info = await lstat(resolved);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new DownloadActionError(`${name} must name a regular file`);
  }
  return resolved;
}

async function resolveCacheRoot(value: string, runnerTemp: string): Promise<string> {
  if (value.length !== 0 && !path.isAbsolute(value)) {
    throw new DownloadActionError('cache-root must be absolute');
  }
  const root =
    value.length === 0
      ? path.join(runnerTemp, 'debz-package-cache')
      : path.resolve(value);
  if (!path.isAbsolute(root) || !isWithin(runnerTemp, root) || root === runnerTemp) {
    throw new DownloadActionError('cache-root must be an absolute child of RUNNER_TEMP');
  }
  rejectAmbiguousComponents(root, 'cache-root');
  await createSafeDirectory(root, runnerTemp);
  return root;
}

async function createSafeDirectory(target: string, trustedRoot: string): Promise<void> {
  const root = await realpath(trustedRoot);
  if (root !== path.resolve(trustedRoot)) {
    throw new DownloadActionError('RUNNER_TEMP must not traverse a symbolic link');
  }
  const relative = path.relative(root, target);
  if (relative.length === 0 || relative.startsWith(`..${path.sep}`) || relative === '..') {
    throw new DownloadActionError('cache path escapes RUNNER_TEMP');
  }
  let current = root;
  for (const component of relative.split(path.sep)) {
    if (component.length === 0 || component === '.' || component === '..') {
      throw new DownloadActionError('cache path contains an ambiguous component');
    }
    current = path.join(current, component);
    try {
      const info = await lstat(current);
      if (!info.isDirectory() || info.isSymbolicLink()) {
        throw new DownloadActionError('cache path contains a non-directory or symbolic link');
      }
    } catch (error) {
      if (error instanceof DownloadActionError) throw error;
      await mkdir(current, { mode: 0o700 });
    }
  }
  if ((await realpath(target)) !== path.resolve(target)) {
    throw new DownloadActionError('cache path must not traverse a symbolic link');
  }
}

function requiredEnvironmentPath(
  environment: RuntimeEnvironment,
  name: string,
): string {
  const value = environment[name] ?? '';
  if (!path.isAbsolute(value)) {
    throw new DownloadActionError(`${name} must be an absolute path`);
  }
  rejectAmbiguousComponents(value, name);
  return path.resolve(value);
}

function rejectAmbiguousComponents(value: string, name: string): void {
  if (value.includes('\0')) {
    throw new DownloadActionError(`${name} contains a NUL byte`);
  }
  const components = value.split(/[\\/]/u);
  if (components.some((component) => component === '.' || component === '..')) {
    throw new DownloadActionError(`${name} contains an ambiguous path component`);
  }
}

function isWithin(parent: string, child: string): boolean {
  const relative = path.relative(path.resolve(parent), path.resolve(child));
  return (
    relative.length === 0 ||
    (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative))
  );
}

function inputName(name: string): string {
  return name.toLowerCase().replaceAll('_', '-');
}

function inputValue(environment: RuntimeEnvironment, name: string): string {
  return (
    environment[`${INPUT_PREFIX}${name}`] ??
    environment[`INPUT_${name.replaceAll('_', '-').toUpperCase()}`] ??
    ''
  );
}
