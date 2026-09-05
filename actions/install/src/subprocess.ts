import { spawn } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import {
  access,
  chmod,
  lstat,
  mkdtemp,
  open,
  realpath,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';

import { InstallActionError } from './errors.js';
import type { Inputs } from './inputs.js';

const setupOutputNames = new Set([
  'debz-path',
  'debz-version',
  'target',
  'cache-hit',
]);
const downloadOutputNames = new Set([
  'cache-hit',
  'cache-matched-key',
  'cache-path',
  'cache-root',
  'lock-digest',
  'downloaded-count',
  'reused-count',
]);
const setupStateNames = new Set([
  'debz-cache-path',
  'debz-cache-key',
  'debz-cache-expected-root',
  'debz-cache-asset-size',
  'debz-cache-archive-digest',
  'debz-cache-version',
]);

export interface SetupOutputs {
  debzPath: string;
  debzVersion: string;
  target: string;
  cacheHit: boolean;
}

export interface DownloadOutputs {
  cacheHit: boolean;
  matchedKey: string;
  cachePath: string;
  cacheRoot: string;
  lockDigest: string;
  downloadedCount: number;
  reusedCount: number;
}

export interface CommandExecution {
  code: number;
  stdout: string;
  stderr: string;
}

export class BundledActionRunner {
  private readonly actionsRoot: string;
  private area?: string;
  private setupState = new Map<string, string>();

  constructor(private readonly inputs: Inputs) {
    this.actionsRoot = path.dirname(inputs.actionPath);
  }

  async setup(): Promise<SetupOutputs> {
    const area = await this.transferArea();
    const files = await createCommandFiles(area, 'setup');
    const bundle = await canonicalBundle(
      path.join(this.actionsRoot, 'setup', 'dist', 'main', 'index.js'),
    );
    const environment = childEnvironment({
      GITHUB_ACTION_PATH: path.join(this.actionsRoot, 'setup'),
      GITHUB_WORKSPACE: this.inputs.workspace,
      RUNNER_TEMP: this.inputs.runnerTemp,
      RUNNER_OS: 'Linux',
      RUNNER_ARCH: this.inputs.target === 'linux-x64' ? 'X64' : 'ARM64',
      GITHUB_OUTPUT: files.output,
      GITHUB_PATH: files.path,
      GITHUB_STATE: files.state,
      'INPUT_DEBZ-VERSION': this.inputs.debzVersion,
      INPUT_SHA256: this.inputs.trustedSha256 ?? '',
      INPUT_TOKEN: this.inputs.token ?? '',
      INPUT_CACHE: this.inputs.cliCacheEnabled ? 'true' : 'false',
    });
    await runInherited(process.execPath, [bundle], environment, 'setup action');
    const outputs = await readCommandFile(files.output, setupOutputNames);
    this.setupState = await readCommandFile(files.state, setupStateNames, true);
    if (this.setupState.size !== 0 && this.setupState.size !== setupStateNames.size) {
      throw new InstallActionError('setup action emitted incomplete cache-save state');
    }
    return validateSetupOutputs(outputs, this.inputs);
  }

  async download(debzPath: string): Promise<DownloadOutputs> {
    const area = await this.transferArea();
    const files = await createCommandFiles(area, 'download');
    const bundle = await canonicalBundle(
      path.join(this.actionsRoot, 'download', 'dist', 'index.js'),
    );
    const limits = this.inputs.limits;
    const environment = childEnvironment({
      GITHUB_ACTION_PATH: path.join(this.actionsRoot, 'download'),
      GITHUB_WORKSPACE: this.inputs.workspace,
      RUNNER_TEMP: this.inputs.runnerTemp,
      RUNNER_OS: 'Linux',
      RUNNER_ARCH: this.inputs.target === 'linux-x64' ? 'X64' : 'ARM64',
      GITHUB_OUTPUT: files.output,
      GITHUB_PATH: files.path,
      GITHUB_STATE: files.state,
      PATH: path.dirname(debzPath),
      DEBZ_DOWNLOAD_EXECUTABLE: debzPath,
      DEBZ_DOWNLOAD_LOCK_INPUT: this.inputs.lockInput,
      DEBZ_DOWNLOAD_ARCHITECTURE: this.inputs.architecture,
      DEBZ_DOWNLOAD_SOURCE: this.inputs.sources.join('\n'),
      DEBZ_DOWNLOAD_CONFIG: this.inputs.configs.join('\n'),
      DEBZ_DOWNLOAD_KEYRING: this.inputs.keyrings.join('\n'),
      DEBZ_DOWNLOAD_FOREIGN_ARCHITECTURE:
        this.inputs.foreignArchitectures.join('\n'),
      DEBZ_DOWNLOAD_DEFAULT_RELEASE: this.inputs.defaultRelease ?? '',
      DEBZ_DOWNLOAD_REPOSITORY_POLICY: this.inputs.repositoryPolicy,
      DEBZ_DOWNLOAD_RECOMMENDS: this.inputs.recommends ? 'true' : 'false',
      DEBZ_DOWNLOAD_ALLOW_DOWNGRADE: this.inputs.allowDowngrade
        ? 'true'
        : 'false',
      DEBZ_DOWNLOAD_PROXY: this.inputs.proxy ?? '',
      DEBZ_DOWNLOAD_CREDENTIAL_REFERENCE:
        this.inputs.credentialReference ?? '',
      DEBZ_DOWNLOAD_DEADLINE_MS:
        this.inputs.deadlineMs === undefined ? '' : String(this.inputs.deadlineMs),
      DEBZ_DOWNLOAD_LOCK_WAIT_MS: String(this.inputs.lockWaitMs),
      DEBZ_DOWNLOAD_MAXIMUM_PACKAGE_BYTES: String(limits.maximumPackageBytes),
      DEBZ_DOWNLOAD_MAXIMUM_TOTAL_PACKAGE_BYTES: String(
        limits.maximumTotalPackageBytes,
      ),
      DEBZ_DOWNLOAD_MAXIMUM_LOCK_PACKAGES: String(limits.maximumLockPackages),
      DEBZ_DOWNLOAD_MAXIMUM_REPOSITORY_RECORDS: String(
        limits.maximumRepositoryRecords,
      ),
      DEBZ_DOWNLOAD_MAXIMUM_STAGING_ENTRIES: String(
        limits.maximumStagingEntries,
      ),
      DEBZ_DOWNLOAD_MAXIMUM_GC_DIRECTORY_ENTRIES: String(
        limits.maximumGcDirectoryEntries,
      ),
      DEBZ_DOWNLOAD_MAXIMUM_GC_OBJECTS_SCANNED: String(
        limits.maximumGcObjectsScanned,
      ),
      DEBZ_DOWNLOAD_MAXIMUM_GC_OBJECTS_DELETED: String(
        limits.maximumGcObjectsDeleted,
      ),
      DEBZ_DOWNLOAD_MAXIMUM_GC_BYTES_DELETED: String(
        limits.maximumGcBytesDeleted,
      ),
      DEBZ_DOWNLOAD_CACHE: this.inputs.packageCacheEnabled ? 'true' : 'false',
      DEBZ_DOWNLOAD_CACHE_ROOT: this.inputs.cacheRoot,
      DEBZ_DOWNLOAD_OFFLINE: this.inputs.offline ? 'true' : 'false',
      DEBZ_DOWNLOAD_CACHE_ONLY: 'false',
      DEBZ_DOWNLOAD_REPAIR_CORRUPT_CACHE: this.inputs.repairCorruptCache
        ? 'true'
        : 'false',
    });
    await runInherited(process.execPath, [bundle], environment, 'download action');
    return validateDownloadOutputs(
      await readCommandFile(files.output, downloadOutputNames),
      this.inputs,
    );
  }

  async saveSetupCache(): Promise<void> {
    if (this.setupState.size === 0) return;
    const area = await this.transferArea();
    const files = await createCommandFiles(area, 'setup-post');
    const bundle = await canonicalBundle(
      path.join(this.actionsRoot, 'setup', 'dist', 'post', 'index.js'),
    );
    const stateEnvironment: Record<string, string> = {};
    for (const [name, value] of this.setupState) {
      stateEnvironment[`STATE_${name}`] = value;
    }
    const environment = childEnvironment({
      ...stateEnvironment,
      GITHUB_ACTION_PATH: path.join(this.actionsRoot, 'setup'),
      GITHUB_OUTPUT: files.output,
      GITHUB_PATH: files.path,
      GITHUB_STATE: files.state,
    });
    await runInherited(process.execPath, [bundle], environment, 'setup post action');
  }

  async cleanup(): Promise<void> {
    if (this.area !== undefined) {
      await rm(this.area, { recursive: true, force: true });
      this.area = undefined;
    }
  }

  private async transferArea(): Promise<string> {
    if (this.area !== undefined) return this.area;
    const root = await mkdtemp(
      path.join(this.inputs.runnerTemp, 'debz-install-orchestration-'),
    );
    await chmod(root, 0o700);
    if ((await realpath(root)) !== root) {
      throw new InstallActionError(
        'install action orchestration directory is not canonical',
      );
    }
    this.area = root;
    return root;
  }
}

export async function findSudo(): Promise<string> {
  const candidate = '/usr/bin/sudo';
  try {
    const resolved = await realpath(candidate);
    const details = await stat(candidate);
    await access(candidate, fsConstants.X_OK);
    if (resolved !== candidate || !details.isFile()) throw new Error('invalid sudo');
    return candidate;
  } catch {
    throw new InstallActionError(
      "use-sudo requires the canonical executable '/usr/bin/sudo'",
    );
  }
}

export async function runDebz(
  executable: string,
  arguments_: string[],
  sudoPath?: string,
  maximumOutputBytes = 2 * 1024 * 1024,
): Promise<CommandExecution> {
  const command = sudoPath ?? executable;
  const commandArguments =
    sudoPath === undefined ? arguments_ : ['-n', '--', executable, ...arguments_];
  return await runCaptured(
    command,
    commandArguments,
    {
      LANG: 'C',
      LC_ALL: 'C',
    },
    maximumOutputBytes,
  );
}

async function canonicalBundle(filename: string): Promise<string> {
  try {
    const resolved = await realpath(filename);
    const details = await lstat(filename);
    if (
      resolved !== path.resolve(filename) ||
      !details.isFile() ||
      details.isSymbolicLink()
    ) {
      throw new Error('not canonical');
    }
    return resolved;
  } catch {
    throw new InstallActionError(
      'the pinned setup/download action runtime is missing or non-canonical',
    );
  }
}

async function createCommandFiles(
  area: string,
  prefix: string,
): Promise<{ output: string; path: string; state: string }> {
  const files = {
    output: path.join(area, `${prefix}-output`),
    path: path.join(area, `${prefix}-path`),
    state: path.join(area, `${prefix}-state`),
  };
  for (const filename of Object.values(files)) {
    await writeFile(filename, '', { flag: 'wx', mode: 0o600 });
  }
  return files;
}

export function childEnvironment(
  overrides: Record<string, string>,
): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = { ...process.env };
  for (const name of Object.keys(environment)) {
    if (
      name.startsWith('INPUT_') ||
      name.startsWith('DEBZ_INSTALL_') ||
      name.startsWith('DEBZ_DOWNLOAD_') ||
      name.startsWith('STATE_') ||
      name === 'NODE_OPTIONS' ||
      name === 'NODE_PATH'
    ) {
      delete environment[name];
    }
  }
  Object.assign(environment, overrides);
  return environment;
}

async function runInherited(
  executable: string,
  arguments_: string[],
  environment: NodeJS.ProcessEnv,
  label: string,
): Promise<void> {
  const code = await new Promise<number>((resolve, reject) => {
    const child = spawn(executable, arguments_, {
      env: environment,
      stdio: 'inherit',
      windowsHide: true,
    });
    child.once('error', reject);
    child.once('close', (status, signal) => {
      if (signal !== null) {
        reject(new InstallActionError(`${label} terminated by signal ${signal}`));
        return;
      }
      resolve(status ?? 1);
    });
  });
  if (code !== 0) {
    throw new InstallActionError(`${label} failed with exit code ${code}`);
  }
}

async function runCaptured(
  executable: string,
  arguments_: string[],
  environment: NodeJS.ProcessEnv,
  maximumOutputBytes: number,
): Promise<CommandExecution> {
  return await new Promise<CommandExecution>((resolve, reject) => {
    const child = spawn(executable, arguments_, {
      detached: true,
      env: environment,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let excessive = false;
    let terminationError: unknown;
    const append = (chunks: Buffer[], value: Buffer, isStdout: boolean) => {
      if (excessive) return;
      if (isStdout) stdoutBytes += value.length;
      else stderrBytes += value.length;
      if (stdoutBytes + stderrBytes > maximumOutputBytes) {
        excessive = true;
        try {
          if (child.pid === undefined) throw new Error('missing child process ID');
          process.kill(-child.pid, 'SIGKILL');
        } catch (error) {
          terminationError = error;
          child.kill('SIGKILL');
        }
        return;
      }
      chunks.push(value);
    };
    child.stdout.on('data', (value: Buffer) => append(stdout, value, true));
    child.stderr.on('data', (value: Buffer) => append(stderr, value, false));
    child.once('error', reject);
    child.once('close', (status, signal) => {
      if (excessive) {
        reject(
          new InstallActionError(
            terminationError === undefined
              ? 'debz output exceeded its bounded limit'
              : 'debz output exceeded its bounded limit and its process group could not be terminated',
            terminationError === undefined ? undefined : { cause: terminationError },
          ),
        );
        return;
      }
      if (signal !== null) {
        reject(new InstallActionError(`debz terminated by signal ${signal}`));
        return;
      }
      resolve({
        code: status ?? 1,
        stdout: Buffer.concat(stdout, stdoutBytes).toString('utf8'),
        stderr: Buffer.concat(stderr, stderrBytes).toString('utf8'),
      });
    });
  });
}

async function readCommandFile(
  filename: string,
  allowedNames: Set<string>,
  allowSubset = false,
): Promise<Map<string, string>> {
  const handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const details = await handle.stat();
    if (!details.isFile() || details.size > 64 * 1024) {
      throw new InstallActionError('child action command file is invalid');
    }
    const text = await handle.readFile({ encoding: 'utf8' });
    if (text.includes('\0') || text.includes('\r')) {
      throw new InstallActionError('child action command file is not canonical');
    }
    return parseCommandFile(text, allowedNames, allowSubset);
  } finally {
    await handle.close();
  }
}

export function parseCommandFile(
  text: string,
  allowedNames: Set<string>,
  allowSubset = false,
): Map<string, string> {
  if (text.includes('\0') || text.includes('\r')) {
    throw new InstallActionError('child action command file is not canonical');
  }
  const lines = text.split('\n');
  if (lines.at(-1) === '') lines.pop();
  const outputs = new Map<string, string>();
  for (let index = 0; index < lines.length; ) {
    const match = /^([A-Za-z0-9_-]+)<<([A-Za-z0-9_-]+)$/u.exec(
      lines[index] ?? '',
    );
    if (match === null) {
      throw new InstallActionError('child action command file is malformed');
    }
    const [, name, delimiter] = match;
    index += 1;
    const values: string[] = [];
    while (index < lines.length && lines[index] !== delimiter) {
      values.push(lines[index]);
      index += 1;
    }
    if (index >= lines.length || values.length !== 1) {
      throw new InstallActionError('child action output must be one bounded line');
    }
    index += 1;
    if (!allowedNames.has(name) || outputs.has(name)) {
      throw new InstallActionError(
        'child action emitted an unexpected or duplicate output',
      );
    }
    outputs.set(name, values[0]);
  }
  if (!allowSubset && outputs.size !== allowedNames.size) {
    throw new InstallActionError('child action omitted a required output');
  }
  return outputs;
}

function validateSetupOutputs(
  outputs: Map<string, string>,
  inputs: Inputs,
): SetupOutputs {
  const debzPath = requiredOutput(outputs, 'debz-path');
  const debzVersion = requiredOutput(outputs, 'debz-version');
  const target = requiredOutput(outputs, 'target');
  const cacheHit = booleanOutput(outputs, 'cache-hit');
  if (!path.isAbsolute(debzPath) || debzVersion !== inputs.debzVersion) {
    throw new InstallActionError('setup action returned an unexpected CLI identity');
  }
  if (target !== inputs.target) {
    throw new InstallActionError('setup action returned the wrong native target');
  }
  return { debzPath, debzVersion, target, cacheHit };
}

function validateDownloadOutputs(
  outputs: Map<string, string>,
  inputs: Inputs,
): DownloadOutputs {
  const cacheHit = booleanOutput(outputs, 'cache-hit');
  const matchedKey = requiredOutput(outputs, 'cache-matched-key', true);
  const cachePath = requiredOutput(outputs, 'cache-path');
  const cacheRoot = requiredOutput(outputs, 'cache-root');
  const lockDigest = requiredOutput(outputs, 'lock-digest');
  const downloadedCount = countOutput(outputs, 'downloaded-count');
  const reusedCount = countOutput(outputs, 'reused-count');
  if (
    cachePath !== inputs.cachePath ||
    cacheRoot !== inputs.cacheRoot ||
    !/^[0-9a-f]{64}$/u.test(lockDigest)
  ) {
    throw new InstallActionError(
      'download action returned an unexpected cache or lock identity',
    );
  }
  if (
    matchedKey.includes('\n') ||
    (matchedKey.length !== 0 &&
      !/^debz-package-cas-v1-[A-Za-z0-9-]+-[0-9a-f]{64}-[0-9a-f]{64}$/u.test(
        matchedKey,
      )) ||
    (cacheHit && matchedKey.length === 0) ||
    (!cacheHit && matchedKey.length > 512)
  ) {
    throw new InstallActionError('download action returned invalid cache-hit evidence');
  }
  return {
    cacheHit,
    matchedKey,
    cachePath,
    cacheRoot,
    lockDigest,
    downloadedCount,
    reusedCount,
  };
}

function requiredOutput(
  outputs: Map<string, string>,
  name: string,
  allowEmpty = false,
): string {
  const value = outputs.get(name);
  if (
    value === undefined ||
    (!allowEmpty && value.length === 0) ||
    value.includes('\0') ||
    value.includes('\r') ||
    value.includes('\n')
  ) {
    throw new InstallActionError(`child action output '${name}' is invalid`);
  }
  return value;
}

function booleanOutput(outputs: Map<string, string>, name: string): boolean {
  const value = requiredOutput(outputs, name);
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new InstallActionError(`child action output '${name}' is not boolean`);
}

function countOutput(outputs: Map<string, string>, name: string): number {
  const value = requiredOutput(outputs, name);
  if (!/^(0|[1-9]\d*)$/u.test(value)) {
    throw new InstallActionError(`child action output '${name}' is not a count`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new InstallActionError(`child action output '${name}' is unbounded`);
  }
  return parsed;
}
