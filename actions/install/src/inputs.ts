import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  access,
  lstat,
  mkdir,
  realpath,
  stat,
} from 'node:fs/promises';
import path from 'node:path';

import { InstallActionError } from './errors.js';

const INPUT_PREFIX = 'DEBZ_INSTALL_';
const semverPattern =
  /^(?:v)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const sha256Pattern = /^[0-9a-f]{64}$/;
const packagePattern =
  /^[a-z0-9][a-z0-9+.-]{0,253}(?::[a-z0-9][a-z0-9-]{0,63})?(?:=[0-9A-Za-z][0-9A-Za-z.+:_-]{0,254})?$/;
const architecturePattern = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;
const forceValues = new Set([
  'depends',
  'depends_version',
  'break_replaces',
  'overwrite',
  'overwrite_dir',
  'remove_reinstreq',
]);

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
  workspace: string;
  runnerTemp: string;
  actionPath: string;
  package: string;
  lockInput: string;
  architecture: 'amd64' | 'arm64';
  target: 'linux-x64' | 'linux-arm64';
  installRoot: string;
  statePath: string;
  conffile: 'keep-existing' | 'use-package-version';
  forces: string[];
  useSudo: boolean;
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
  packageCacheEnabled: boolean;
  cacheRoot: string;
  cachePath: string;
  offline: boolean;
  repairCorruptCache: boolean;
  debzVersion: string;
  trustedSha256?: string;
  token?: string;
  cliCacheEnabled: boolean;
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
  const workspace = await existingCanonicalDirectory(
    requiredEnvironmentPath(environment, 'GITHUB_WORKSPACE'),
    'GITHUB_WORKSPACE',
  );
  const runnerTemp = await existingCanonicalDirectory(
    requiredEnvironmentPath(environment, 'RUNNER_TEMP'),
    'RUNNER_TEMP',
  );
  const actionPath = await existingCanonicalDirectory(
    requiredEnvironmentPath(environment, 'GITHUB_ACTION_PATH'),
    'GITHUB_ACTION_PATH',
  );
  const { architecture, target } = validateRunner(environment, runtime);

  const packageSelector = exactScalar(environment, 'PACKAGE', true);
  if (
    packageSelector.length > 255 ||
    !packagePattern.test(packageSelector) ||
    packageSelector.startsWith('-')
  ) {
    throw new InstallActionError(
      'package must be one explicit debz install selector without whitespace or a leading dash',
    );
  }
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
    throw new InstallActionError(
      "one or more explicit 'source' or 'config' paths are required",
    );
  }
  const keyrings = await resolveFileList(
    multiline(environment, 'KEYRING', true),
    workspace,
    'keyring',
  );
  if (keyrings.length === 0) {
    throw new InstallActionError("one or more explicit 'keyring' paths are required");
  }

  const requestedArchitecture = exactScalar(environment, 'ARCHITECTURE', true);
  if (requestedArchitecture !== architecture) {
    throw new InstallActionError(
      `architecture must match the native ${architecture} runner architecture`,
    );
  }
  const foreignArchitectures = lineList(
    multiline(environment, 'FOREIGN_ARCHITECTURE'),
    'foreign-architecture',
    16,
  );
  for (const foreign of foreignArchitectures) {
    if (
      !architecturePattern.test(foreign) ||
      (foreign !== 'amd64' && foreign !== 'arm64') ||
      foreign === architecture
    ) {
      throw new InstallActionError(`invalid foreign architecture '${foreign}'`);
    }
  }

  if (exactScalar(environment, 'ASSUME_YES', true) !== 'true') {
    throw new InstallActionError(
      "assume-yes must be exactly 'true' to authorize mutation",
    );
  }
  if (exactScalar(environment, 'NONINTERACTIVE', true) !== 'true') {
    throw new InstallActionError(
      "noninteractive must be exactly 'true'; interactive Actions installs are unsupported",
    );
  }
  const conffile = exactScalar(environment, 'CONFFILE', true);
  if (conffile !== 'keep-existing' && conffile !== 'use-package-version') {
    throw new InstallActionError(
      "conffile must be 'keep-existing' or 'use-package-version'",
    );
  }
  const forces = exactLineList(exactMultiline(environment, 'FORCE'), 'force', 6);
  for (const force of forces) {
    if (!forceValues.has(force)) {
      throw new InstallActionError(`invalid force policy '${force}'`);
    }
  }

  const repositoryPolicy = exactScalar(environment, 'REPOSITORY_POLICY', true);
  if (repositoryPolicy !== 'strict-priority' && repositoryPolicy !== 'best-version') {
    throw new InstallActionError(
      "repository-policy must be 'strict-priority' or 'best-version'",
    );
  }
  const recommends = booleanInput(environment, 'RECOMMENDS');
  const allowDowngrade = booleanInput(environment, 'ALLOW_DOWNGRADE');
  const packageCacheEnabled = booleanInput(environment, 'CACHE');
  const cliCacheEnabled = booleanInput(environment, 'CLI_CACHE');
  const offlineInput = booleanInput(environment, 'OFFLINE');
  const cacheOnlyInput = booleanInput(environment, 'CACHE_ONLY');
  const offline = offlineInput || cacheOnlyInput;
  const repairCorruptCache = booleanInput(environment, 'REPAIR_CORRUPT_CACHE');
  if (offline && repairCorruptCache) {
    throw new InstallActionError(
      'repair-corrupt-cache cannot be enabled with offline/cache-only mode',
    );
  }
  const useSudo = booleanInput(environment, 'USE_SUDO');
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
      9 * 1024 * 1024 * 1024,
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

  const defaultRelease = optionalExactScalar(environment, 'DEFAULT_RELEASE');
  if (
    defaultRelease !== undefined &&
    !/^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$/.test(defaultRelease)
  ) {
    throw new InstallActionError('default-release has an invalid spelling');
  }
  const proxy = optionalExactScalar(environment, 'PROXY');
  if (proxy !== undefined) validateProxy(proxy);
  const credentialValue = scalar(environment, 'CREDENTIAL_REFERENCE');
  const credentialReference =
    credentialValue.length === 0
      ? undefined
      : await resolveRegularFile(
          credentialValue,
          workspace,
          'credential-reference',
        );

  const debzVersion = normalizeVersion(
    exactScalar(environment, 'DEBZ_VERSION', true),
  );
  const sha256Value = exactScalar(environment, 'SHA256');
  const trustedSha256 =
    sha256Value.length === 0 ? undefined : normalizeSha256(sha256Value);
  const tokenValue = rawInput(environment, 'TOKEN');
  if (
    tokenValue.includes('\0') ||
    tokenValue.includes('\r') ||
    tokenValue.includes('\n') ||
    tokenValue !== tokenValue.trim()
  ) {
    throw new InstallActionError('token must not contain whitespace or line breaks');
  }
  const token = tokenValue.length === 0 ? undefined : tokenValue;

  const installRoot = await resolvePlannedDirectory(
    scalar(environment, 'INSTALL_ROOT', true),
    workspace,
    'install-root',
    true,
  );
  if (installRoot === path.parse(installRoot).root) {
    throw new InstallActionError('install-root must not be the host root');
  }
  const stateValue = scalar(environment, 'STATE_PATH');
  const statePath =
    stateValue.length === 0
      ? path.join(
          runnerTemp,
          'debz-install-state',
          createHash('sha256').update(installRoot).digest('hex').slice(0, 32),
        )
      : await resolvePlannedDirectory(
          stateValue,
          workspace,
          'state-path',
          true,
        );
  const cacheValue = scalar(environment, 'CACHE_ROOT');
  if (cacheValue.length !== 0 && !path.isAbsolute(cacheValue)) {
    throw new InstallActionError('cache-root must be absolute');
  }
  const cacheRoot = await resolvePlannedDirectory(
    cacheValue.length === 0
      ? path.join(runnerTemp, 'debz-package-cache')
      : cacheValue,
    runnerTemp,
    'cache-root',
    false,
  );
  if (!isStrictChild(runnerTemp, cacheRoot)) {
    throw new InstallActionError(
      'cache-root must be an absolute child of RUNNER_TEMP',
    );
  }
  const cachePath = path.join(cacheRoot, 'packages-v1', 'objects');
  await assertNoSymlinkComponents(cachePath, 'package cache path');

  const mutablePaths = [
    ['install-root', installRoot],
    ['state-path', statePath],
    ['cache-root', cacheRoot],
  ] as const;
  const setupPaths = [
    path.join(runnerTemp, 'debz-tools'),
    path.join(runnerTemp, 'debz-setup-tmp'),
    path.join(runnerTemp, 'debz-sigstore-tuf-v1'),
  ];
  for (let left = 0; left < mutablePaths.length; left += 1) {
    for (let right = left + 1; right < mutablePaths.length; right += 1) {
      if (pathsOverlap(mutablePaths[left][1], mutablePaths[right][1])) {
        throw new InstallActionError(
          `${mutablePaths[left][0]} and ${mutablePaths[right][0]} must not overlap`,
        );
      }
    }
  }
  const protectedPaths = [
    lockInput,
    ...sources,
    ...configs,
    ...keyrings,
    ...(credentialReference === undefined ? [] : [credentialReference]),
  ];
  for (const [name, mutable] of mutablePaths) {
    if (pathsOverlap(mutable, actionPath)) {
      throw new InstallActionError(`${name} must not overlap the action runtime`);
    }
    if (setupPaths.some((setupPath) => pathsOverlap(mutable, setupPath))) {
      throw new InstallActionError(`${name} must not overlap setup runtime state`);
    }
    if (protectedPaths.some((protectedPath) => pathsOverlap(mutable, protectedPath))) {
      throw new InstallActionError(
        `lock, repository, keyring, and credential files must be outside ${name}`,
      );
    }
  }

  return {
    workspace,
    runnerTemp,
    actionPath,
    package: packageSelector,
    lockInput,
    architecture,
    target,
    installRoot,
    statePath,
    conffile,
    forces,
    useSudo,
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
    packageCacheEnabled,
    cacheRoot,
    cachePath,
    offline,
    repairCorruptCache,
    debzVersion,
    trustedSha256,
    token,
    cliCacheEnabled,
  };
}

export async function prepareDirectories(inputs: Inputs): Promise<void> {
  await ensureSafeDirectory(inputs.installRoot);
  await ensureSafeDirectory(inputs.statePath);
  await ensureSafeDirectory(inputs.cacheRoot);
  await assertCanonicalDirectory(inputs.installRoot, 'install-root');
  await assertCanonicalDirectory(inputs.statePath, 'state-path');
  await assertCanonicalDirectory(inputs.cacheRoot, 'cache-root');
}

function validateRunner(
  environment: RuntimeEnvironment,
  runtime: { platform: NodeJS.Platform; architecture: string },
): {
  architecture: 'amd64' | 'arm64';
  target: 'linux-x64' | 'linux-arm64';
} {
  const runnerOs = environment.RUNNER_OS ?? '';
  const runnerArchitecture = environment.RUNNER_ARCH ?? '';
  if (
    runnerOs === 'Linux' &&
    runtime.platform === 'linux' &&
    runnerArchitecture === 'X64' &&
    runtime.architecture === 'x64'
  ) {
    return { architecture: 'amd64', target: 'linux-x64' };
  }
  if (
    runnerOs === 'Linux' &&
    runtime.platform === 'linux' &&
    runnerArchitecture === 'ARM64' &&
    runtime.architecture === 'arm64'
  ) {
    return { architecture: 'arm64', target: 'linux-arm64' };
  }
  throw new InstallActionError(
    `unsupported runner ${runnerOs || 'unknown'}/${runnerArchitecture || 'unknown'} (${runtime.platform}/${runtime.architecture})`,
  );
}

function normalizeVersion(value: string): string {
  const match = semverPattern.exec(value);
  if (match === null) {
    throw new InstallActionError(
      'debz-version must be one exact SemVer; ranges and latest are not allowed',
    );
  }
  const major = Number(match[1]);
  const minor = Number(match[2]);
  if (major === 0 && minor < 3) {
    throw new InstallActionError(
      'debz-version must be v0.3.0 or newer for the package-cache and transaction-result contracts',
    );
  }
  return value.startsWith('v') ? value : `v${value}`;
}

function normalizeSha256(value: string): string {
  const normalized = value.toLowerCase();
  if (!sha256Pattern.test(normalized)) {
    throw new InstallActionError('sha256 must be exactly 64 hexadecimal characters');
  }
  return normalized;
}

function validateProxy(value: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new InstallActionError('proxy must be an absolute HTTP(S) URI');
  }
  if (
    (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
    parsed.username.length !== 0 ||
    parsed.password.length !== 0 ||
    parsed.search.length !== 0 ||
    parsed.hash.length !== 0
  ) {
    throw new InstallActionError(
      'proxy must be an HTTP(S) origin without credentials, query, or fragment',
    );
  }
}

async function resolveFileList(
  value: string,
  workspace: string,
  name: string,
): Promise<string[]> {
  const entries = lineList(value, name, 64);
  const resolved: string[] = [];
  for (const entry of entries) {
    resolved.push(await resolveRegularFile(entry, workspace, name));
  }
  if (new Set(resolved).size !== resolved.length) {
    throw new InstallActionError(`${name} resolves to a duplicate path`);
  }
  return resolved;
}

async function resolveRegularFile(
  value: string,
  workspace: string,
  name: string,
): Promise<string> {
  rejectAmbiguousPath(value, name);
  const candidate = path.isAbsolute(value)
    ? path.resolve(value)
    : path.resolve(workspace, value);
  if (!path.isAbsolute(value) && !isWithin(workspace, candidate)) {
    throw new InstallActionError(`${name} escapes GITHUB_WORKSPACE`);
  }
  let resolved: string;
  try {
    resolved = await realpath(candidate);
  } catch {
    throw new InstallActionError(`${name} does not exist`);
  }
  if (resolved !== candidate) {
    throw new InstallActionError(`${name} must not traverse a symbolic link`);
  }
  const info = await lstat(candidate);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new InstallActionError(`${name} must name a regular file`);
  }
  return resolved;
}

async function resolvePlannedDirectory(
  value: string,
  base: string,
  name: string,
  allowRelative: boolean,
): Promise<string> {
  rejectAmbiguousPath(value, name);
  if (!allowRelative && !path.isAbsolute(value)) {
    throw new InstallActionError(`${name} must be absolute`);
  }
  const candidate = path.isAbsolute(value)
    ? path.resolve(value)
    : path.resolve(base, value);
  if (!path.isAbsolute(value) && !isWithin(base, candidate)) {
    throw new InstallActionError(`${name} escapes GITHUB_WORKSPACE`);
  }
  await assertNoSymlinkComponents(candidate, name);
  return candidate;
}

async function assertNoSymlinkComponents(target: string, name: string): Promise<void> {
  const parsed = path.parse(target);
  let current = parsed.root;
  for (const component of target.slice(parsed.root.length).split(path.sep)) {
    current = path.join(current, component);
    try {
      const info = await lstat(current);
      if (info.isSymbolicLink()) {
        throw new InstallActionError(`${name} must not traverse a symbolic link`);
      }
      if (!info.isDirectory()) {
        throw new InstallActionError(`${name} contains a non-directory component`);
      }
    } catch (error) {
      if (error instanceof InstallActionError) throw error;
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') return;
      throw new InstallActionError(`${name} could not be inspected`, { cause: error });
    }
  }
}

async function ensureSafeDirectory(target: string): Promise<void> {
  const parsed = path.parse(target);
  let current = parsed.root;
  for (const component of target.slice(parsed.root.length).split(path.sep)) {
    current = path.join(current, component);
    try {
      const info = await lstat(current);
      if (!info.isDirectory() || info.isSymbolicLink()) {
        throw new InstallActionError(
          `${target} contains a non-directory or symbolic-link component`,
        );
      }
    } catch (error) {
      if (error instanceof InstallActionError) throw error;
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      try {
        await mkdir(current, { mode: 0o700 });
      } catch (mkdirError) {
        if ((mkdirError as NodeJS.ErrnoException).code !== 'EEXIST') {
          throw mkdirError;
        }
      }
      const created = await lstat(current);
      if (!created.isDirectory() || created.isSymbolicLink()) {
        throw new InstallActionError(
          `${target} changed while its directory tree was created`,
        );
      }
    }
  }
}

async function existingCanonicalDirectory(
  value: string,
  name: string,
): Promise<string> {
  rejectAmbiguousPath(value, name);
  const normalized = path.resolve(value);
  let resolved: string;
  try {
    resolved = await realpath(normalized);
  } catch {
    throw new InstallActionError(`${name} does not exist`);
  }
  if (resolved !== normalized) {
    throw new InstallActionError(`${name} must not traverse a symbolic link`);
  }
  const details = await stat(normalized);
  if (!details.isDirectory()) {
    throw new InstallActionError(`${name} must be a directory`);
  }
  return normalized;
}

async function assertCanonicalDirectory(target: string, name: string): Promise<void> {
  const resolved = await realpath(target);
  const info = await lstat(target);
  if (resolved !== path.resolve(target) || !info.isDirectory() || info.isSymbolicLink()) {
    throw new InstallActionError(`${name} is not a canonical directory`);
  }
  await access(target, fsConstants.R_OK | fsConstants.X_OK);
}

function lineList(value: string, name: string, maximum: number): string[] {
  if (value.length === 0) return [];
  const entries = value.split(/\r?\n/u).map((entry) => entry.trim());
  if (entries.some((entry) => entry.length === 0 || entry.includes('\0'))) {
    throw new InstallActionError(`${name} contains an empty or invalid line`);
  }
  if (entries.length > maximum) {
    throw new InstallActionError(`${name} exceeds ${maximum} entries`);
  }
  if (new Set(entries).size !== entries.length) {
    throw new InstallActionError(`${name} contains a duplicate entry`);
  }
  return entries;
}

function exactLineList(value: string, name: string, maximum: number): string[] {
  if (value.length === 0) return [];
  const entries = value.split(/\r?\n/u);
  if (
    entries.some(
      (entry) =>
        entry.length === 0 ||
        entry !== entry.trim() ||
        entry.includes('\0'),
    )
  ) {
    throw new InstallActionError(
      `${name} entries must use exact non-empty spellings`,
    );
  }
  if (entries.length > maximum) {
    throw new InstallActionError(`${name} exceeds ${maximum} entries`);
  }
  if (new Set(entries).size !== entries.length) {
    throw new InstallActionError(`${name} contains a duplicate entry`);
  }
  return entries;
}

function booleanInput(environment: RuntimeEnvironment, name: string): boolean {
  const value = exactScalar(environment, name, true);
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new InstallActionError(`${inputName(name)} must be exactly 'true' or 'false'`);
}

function positiveInteger(
  environment: RuntimeEnvironment,
  name: string,
  maximum: number,
): number {
  const value = exactScalar(environment, name, true);
  if (!/^[1-9]\d*$/.test(value)) {
    throw new InstallActionError(`${inputName(name)} must be a positive integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) {
    throw new InstallActionError(
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
  return exactScalar(environment, name).length === 0
    ? undefined
    : positiveInteger(environment, name, maximum);
}

function scalar(
  environment: RuntimeEnvironment,
  name: string,
  required = false,
): string {
  const value = rawInput(environment, name);
  if (value.includes('\0') || value.includes('\r') || value.includes('\n')) {
    throw new InstallActionError(`${inputName(name)} must be a single-line value`);
  }
  const trimmed = value.trim();
  if (required && trimmed.length === 0) {
    throw new InstallActionError(`${inputName(name)} is required`);
  }
  return trimmed;
}

function exactScalar(
  environment: RuntimeEnvironment,
  name: string,
  required = false,
): string {
  const value = rawInput(environment, name);
  if (
    value.includes('\0') ||
    value.includes('\r') ||
    value.includes('\n') ||
    value !== value.trim()
  ) {
    throw new InstallActionError(
      `${inputName(name)} must use one exact single-line value`,
    );
  }
  if (required && value.length === 0) {
    throw new InstallActionError(`${inputName(name)} is required`);
  }
  return value;
}

function optionalExactScalar(
  environment: RuntimeEnvironment,
  name: string,
): string | undefined {
  const value = exactScalar(environment, name);
  return value.length === 0 ? undefined : value;
}

function multiline(
  environment: RuntimeEnvironment,
  name: string,
  required = false,
): string {
  const value = rawInput(environment, name);
  if (value.includes('\0')) {
    throw new InstallActionError(`${inputName(name)} contains a NUL byte`);
  }
  const trimmed = value.trim();
  if (required && trimmed.length === 0) {
    throw new InstallActionError(`${inputName(name)} is required`);
  }
  return trimmed;
}

function exactMultiline(
  environment: RuntimeEnvironment,
  name: string,
): string {
  const value = rawInput(environment, name);
  if (value.includes('\0') || value !== value.trim()) {
    throw new InstallActionError(
      `${inputName(name)} entries must use exact non-empty spellings`,
    );
  }
  return value;
}

function requiredEnvironmentPath(
  environment: RuntimeEnvironment,
  name: string,
): string {
  const value = environment[name] ?? '';
  if (!path.isAbsolute(value)) {
    throw new InstallActionError(`${name} must be an absolute path`);
  }
  return value;
}

function rejectAmbiguousPath(value: string, name: string): void {
  if (
    value.length === 0 ||
    value.includes('\0') ||
    value.includes('\\') ||
    (value.endsWith(path.sep) && value !== path.parse(value).root)
  ) {
    throw new InstallActionError(`${name} contains an invalid path spelling`);
  }
  if (value === path.parse(value).root) return;
  const start = path.isAbsolute(value) ? 1 : 0;
  const components = value.slice(start).split(path.sep);
  if (
    components.some(
      (component) =>
        component.length === 0 || component === '.' || component === '..',
    )
  ) {
    throw new InstallActionError(`${name} contains an ambiguous path component`);
  }
}

function pathsOverlap(left: string, right: string): boolean {
  return isWithin(left, right) || isWithin(right, left);
}

function isWithin(parent: string, child: string): boolean {
  const relative = path.relative(path.resolve(parent), path.resolve(child));
  return (
    relative.length === 0 ||
    (!relative.startsWith(`..${path.sep}`) &&
      relative !== '..' &&
      !path.isAbsolute(relative))
  );
}

function isStrictChild(parent: string, child: string): boolean {
  return parent !== child && isWithin(parent, child);
}

function inputName(name: string): string {
  return name.toLowerCase().replaceAll('_', '-');
}

function rawInput(environment: RuntimeEnvironment, name: string): string {
  return (
    environment[`${INPUT_PREFIX}${name}`] ??
    environment[`INPUT_${name.replaceAll('_', '-').toUpperCase()}`] ??
    ''
  );
}
