import assert from 'node:assert/strict';
import { chmod, copyFile, mkdir, readdir } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  defaultServices,
  runAction,
  type ActionIO,
  type CompositionRunner,
} from '../src/action.js';
import { DebzInstallExitError } from '../src/errors.js';
import { readInputs, type Inputs, type RuntimeEnvironment } from '../src/inputs.js';
import { BundledActionRunner } from '../src/subprocess.js';

const enabled = process.env.DEBZ_INSTALL_INTEGRATION === '1';
const actionPath = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../..',
);

test(
  'installs cold, warm fresh-root, offline, and same-root closures',
  { skip: !enabled, timeout: 180_000 },
  async () => {
    const fixtureRoot = requiredPath('DEBZ_INSTALL_FIXTURE_ROOT');
    const sourceCli = requiredPath('DEBZ_INSTALL_CLI');
    const architecture = requiredValue('DEBZ_INSTALL_ARCHITECTURE');
    const runnerArchitecture = architecture === 'amd64' ? 'X64' : 'ARM64';
    const runnerTemp = path.join(fixtureRoot, 'runner');
    const localCli = path.join(
      runnerTemp,
      'debz-tools',
      '0.3.0',
      architecture,
      'bin',
      'debz',
    );
    await mkdir(path.dirname(localCli), { recursive: true });
    await copyFile(sourceCli, localCli);
    await chmod(localCli, 0o755);

    const common: RuntimeEnvironment = {
      GITHUB_WORKSPACE: fixtureRoot,
      RUNNER_TEMP: runnerTemp,
      GITHUB_ACTION_PATH: actionPath,
      RUNNER_OS: 'Linux',
      RUNNER_ARCH: runnerArchitecture,
      DEBZ_INSTALL_PACKAGE: 'scenario-main',
      DEBZ_INSTALL_LOCK_INPUT: path.join(fixtureRoot, 'lock.json'),
      DEBZ_INSTALL_ARCHITECTURE: architecture,
      DEBZ_INSTALL_CONFFILE: 'keep-existing',
      DEBZ_INSTALL_ASSUME_YES: 'true',
      DEBZ_INSTALL_NONINTERACTIVE: 'true',
      DEBZ_INSTALL_FORCE: '',
      DEBZ_INSTALL_USE_SUDO:
        process.env.DEBZ_INSTALL_INTEGRATION_SUDO === '1' ? 'true' : 'false',
      DEBZ_INSTALL_SOURCE: path.join(fixtureRoot, 'fixture.sources'),
      DEBZ_INSTALL_CONFIG: '',
      DEBZ_INSTALL_KEYRING: path.join(
        fixtureRoot,
        'repository',
        'fixture-keyring.gpg',
      ),
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
      DEBZ_INSTALL_CACHE: 'false',
      DEBZ_INSTALL_CACHE_ROOT: path.join(runnerTemp, 'cache'),
      DEBZ_INSTALL_OFFLINE: 'false',
      DEBZ_INSTALL_CACHE_ONLY: 'false',
      DEBZ_INSTALL_REPAIR_CORRUPT_CACHE: 'false',
      DEBZ_INSTALL_DEBZ_VERSION: 'v0.3.0',
      DEBZ_INSTALL_SHA256: '',
      DEBZ_INSTALL_TOKEN: '',
      DEBZ_INSTALL_CLI_CACHE: 'false',
    };

    const cold = await execute(
      await inputsFor(common, runnerArchitecture, 'cold', 'keep-existing'),
      localCli,
    );
    assert.equal(cold.get('package-cache-hit'), 'false');
    assert.ok(Number(cold.get('downloaded-count')) > 0);
    assert.ok(Number(cold.get('installed-count')) > 0);

    const warm = await execute(
      await inputsFor(
        common,
        runnerArchitecture,
        'warm-fresh',
        'use-package-version',
      ),
      localCli,
    );
    assert.equal(warm.get('downloaded-count'), '0');
    assert.ok(Number(warm.get('reused-count')) > 0);
    assert.ok(Number(warm.get('installed-count')) > 0);

    const offlineEnvironment = {
      ...common,
      DEBZ_INSTALL_OFFLINE: 'true',
    };
    const offlineInputs = await inputsFor(
      offlineEnvironment,
      runnerArchitecture,
      'offline',
      'keep-existing',
    );
    const offline = await execute(offlineInputs, localCli);
    assert.equal(offline.get('downloaded-count'), '0');
    assert.ok(Number(offline.get('reused-count')) > 0);

    const rerun = await execute(offlineInputs, localCli);
    assert.equal(rerun.get('downloaded-count'), '0');
    assert.equal(
      rerun.get('transaction-result'),
      offline.get('transaction-result'),
    );

    const failureOutputs = new Map<string, string>();
    const failureInputs = await inputsFor(
      {
        ...common,
        DEBZ_INSTALL_PACKAGE: 'fail-script',
        DEBZ_INSTALL_LOCK_INPUT: path.join(fixtureRoot, 'fail.lock.json'),
      },
      runnerArchitecture,
      'failure',
      'keep-existing',
    );
    await assert.rejects(
      execute(failureInputs, localCli, failureOutputs),
      (error: unknown) =>
        error instanceof DebzInstallExitError && error.exitCode === 7,
    );
    assert.equal(failureOutputs.size, 0);
    assert.ok((await readdir(failureInputs.statePath)).length > 0);
  },
);

async function inputsFor(
  common: RuntimeEnvironment,
  runnerArchitecture: string,
  name: string,
  conffile: string,
): Promise<Inputs> {
  return await readInputs(
    {
      ...common,
      DEBZ_INSTALL_INSTALL_ROOT: path.join(
        common.RUNNER_TEMP as string,
        `root-${name}`,
      ),
      DEBZ_INSTALL_STATE_PATH: path.join(
        common.RUNNER_TEMP as string,
        `state-${name}`,
      ),
      DEBZ_INSTALL_CONFFILE: conffile,
    },
    {
      platform: 'linux',
      architecture: runnerArchitecture === 'X64' ? 'x64' : 'arm64',
    },
  );
}

async function execute(
  inputs: Inputs,
  localCli: string,
  outputs = new Map<string, string>(),
): Promise<Map<string, string>> {
  const bundled = new BundledActionRunner(inputs);
  const composition: CompositionRunner = {
    async setup() {
      return {
        debzPath: localCli,
        debzVersion: 'v0.3.0',
        target: inputs.target,
        cacheHit: false,
      };
    },
    async download(debzPath) {
      return await bundled.download(debzPath);
    },
    async saveSetupCache() {},
    async cleanup() {
      await bundled.cleanup();
    },
  };
  const io: ActionIO = {
    info() {},
    error() {},
    setOutput(name, value) {
      outputs.set(name, value);
    },
  };
  await runAction(inputs, io, {
    ...defaultServices,
    createComposition: () => composition,
  });
  return outputs;
}

function requiredPath(name: string): string {
  const value = requiredValue(name);
  if (!path.isAbsolute(value)) throw new Error(`${name} must be absolute`);
  return value;
}

function requiredValue(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}
