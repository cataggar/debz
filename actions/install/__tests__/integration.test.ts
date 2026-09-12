import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  defaultServices,
  runAction,
  type ActionIO,
  type CompositionRunner,
} from '../src/action.js';
import { DebzInstallExitError } from '../src/errors.js';
import { readInputs, type Inputs, type RuntimeEnvironment } from '../src/inputs.js';
import { BundledActionRunner, type CommandExecution } from '../src/subprocess.js';
import { createInputEnvironment } from './helpers.js';
import { buildTransactionResultArguments } from '../src/runner.js';

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

test('native installs bind real receipts across cold, warm, offline, same-root, and failed transactions', {
  skip: !enabled, timeout: 240_000,
}, async () => {
  const base = await mkdtemp(path.join(requiredPath('DEBZ_INSTALL_FIXTURE_ROOT'), 'native-action-'));
  const { environment, workspace, runner } = await createInputEnvironment('fixture', base);
  const architecture = requiredValue('DEBZ_INSTALL_ARCHITECTURE');
  const runnerArchitecture = architecture === 'amd64' ? 'X64' : 'ARM64';
  const sourceCli = requiredPath('DEBZ_INSTALL_CLI');
  environment.GITHUB_ACTION_PATH = actionPath;
  environment.RUNNER_ARCH = runnerArchitecture;
  environment.DEBZ_INSTALL_ARCHITECTURE = architecture;
  environment.DEBZ_INSTALL_TRANSACTION_BACKEND = 'native';
  environment.DEBZ_INSTALL_USE_SUDO = process.env.DEBZ_INSTALL_INTEGRATION_SUDO === '1' ? 'true' : 'false';
  environment.DEBZ_INSTALL_CACHE = 'false';
  environment.DEBZ_INSTALL_CLI_CACHE = 'false';
  const temporary = path.resolve(actionPath, '../../.tmp');
  await mkdir(temporary, { recursive: true });
  const bootstrap = `
import importlib.util, os, shutil, subprocess, sys
from pathlib import Path
repo, workspace, runner = map(Path, sys.argv[1:4])
cli, arch, uid, gid = sys.argv[4:]
def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, repo / "tools" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
generator = load("install_repository", "generate-integration-repository.py")
lifecycle = load("install_lifecycle", "test-native-lifecycle.py")
repository = workspace / "repository"
generator.write_repository(repository, "debian-stable", arch)
keyring = workspace / "keyring.gpg"
shutil.copyfile(repository / "fixture-keyring.gpg", keyring)
source = workspace / "repo.sources"
source.write_text(f"Types: deb\\nURIs: file://{repository}\\nSuites: debian-stable\\nComponents: main\\nArchitectures: {arch}\\nSigned-By: {keyring}\\n")
for name in ("plan", "cold", "warm-fresh", "offline", "failure", "receiptless", "cross-backend"):
    root = runner / f"root-{name}"
    root.mkdir()
    lifecycle.m.make_root(root, arch)
    lifecycle.runtime.copy_program(root, Path("/bin/sh"), "/bin/sh")
    seeds = ["native-helper-target", "essential-core"]
    if name == "receiptless":
        seeds += ["base-dep", "scenario-main"]
    archives = [repository / f"pool/main/{package}_1.0-1_{arch}.deb" for package in seeds]
    assert lifecycle.reference_phase(root, archives, "install", dict(os.environ), root, packages=[]) == 0
for selector, filename, backend in (
    ("scenario-main", "lock.json", "native"), ("fail-script", "fail.lock.json", "native"),
    ("scenario-main", "legacy.lock.json", "legacy_dpkg"),
):
    result = subprocess.run([cli, "plan", "--transaction-backend", backend,
        "--install-root", str(runner / "root-plan"), "--cache-path", str(workspace / "plan-cache"),
        "--state-path", str(workspace / "plan-state"), "--architecture", arch,
        "--source", str(source), "--keyring", str(keyring),
        "--lock-output", str(workspace / filename), "--json", selector],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    assert result.returncode == 0, (result.stdout[-8192:], result.stderr[-8192:])
    os.chown(workspace / filename, int(uid), int(gid))
`;
  const bootstrapArgs = [
    '/usr/bin/env', 'PYTHONDONTWRITEBYTECODE=1', `TMPDIR=${temporary}`,
    `XDG_CACHE_HOME=${path.resolve(actionPath, '../../.cache')}`,
    '/usr/bin/python3', '-c', bootstrap, path.resolve(actionPath, '../..'),
    workspace, runner, sourceCli, architecture,
    String(process.getuid?.() ?? 0), String(process.getgid?.() ?? 0),
  ];
  const elevated = environment.DEBZ_INSTALL_USE_SUDO === 'true';
  await promisify(execFile)(
    elevated ? '/usr/bin/sudo' : bootstrapArgs[0],
    elevated ? ['-n', '--', ...bootstrapArgs] : bootstrapArgs.slice(1),
    {
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1', TMPDIR: temporary },
      timeout: 180_000, maxBuffer: 1024 * 1024,
    },
  );
  const localCli = path.join(runner, 'debz-tools', '0.3.0', 'bin', 'debz');
  await mkdir(path.dirname(localCli), { recursive: true });
  await copyFile(sourceCli, localCli);
  await chmod(localCli, 0o755);
  const observed: string[] = [];
  const runNative = async (inputs: Inputs, outputs = new Map<string, string>()) =>
    await execute(inputs, localCli, outputs, (args, result) => {
      if (result.code === 0 && (args[0] === 'install' || args[1] === 'capabilities')) {
        observed.push(result.stdout);
      }
    });
  const coldInputs = await inputsFor(environment, runnerArchitecture, 'cold', 'keep-existing');
  const cold = await runNative(coldInputs);
  assert.equal(cold.get('changed'), 'true');
  assert.equal(cold.get('installed-count'), '4');
  assert.ok(Number(cold.get('downloaded-count')) > 0);
  assert.equal(cold.get('transaction-result'), path.join(coldInputs.installRoot, 'var/lib/debz/native-transaction-provenance-v1.json'));
  if (process.getuid?.() !== 0) {
    await assert.rejects(readFile(cold.get('transaction-result')!), /EACCES/u);
  }
  const warm = await runNative(await inputsFor(environment, runnerArchitecture, 'warm-fresh', 'use-package-version'));
  assert.equal(warm.get('downloaded-count'), '0');
  assert.equal(warm.get('reused-count'), '4');
  assert.equal(warm.get('changed'), 'true');
  const offlineEnvironment = { ...environment, DEBZ_INSTALL_OFFLINE: 'true' };
  const offlineInputs = await inputsFor(offlineEnvironment, runnerArchitecture, 'offline', 'keep-existing');
  const offline = await runNative(offlineInputs);
  assert.equal(offline.get('downloaded-count'), '0');
  assert.equal(offline.get('changed'), 'true');
  for (const inputs of [
    offlineInputs,
    await inputsFor(offlineEnvironment, runnerArchitecture, 'receiptless', 'keep-existing'),
  ]) {
    // The current install selector deliberately selects the available candidate
    // again. Preserve that reinstall rather than imposing no-op semantics here.
    const repeated = await runNative(inputs);
    assert.equal(repeated.get('changed'), 'true');
    assert.ok(repeated.get('transaction-result'));
    assert.equal(repeated.get('installed-count'), '4');
  }
  const failureInputs = await inputsFor({
    ...environment, DEBZ_INSTALL_PACKAGE: 'fail-script',
    DEBZ_INSTALL_LOCK_INPUT: path.join(workspace, 'fail.lock.json'),
  }, runnerArchitecture, 'failure', 'keep-existing');
  const failureOutputs = new Map<string, string>();
  await assert.rejects(runNative(failureInputs, failureOutputs), (error: unknown) =>
    error instanceof DebzInstallExitError && error.exitCode === 7 &&
    error.statePath === path.join(failureInputs.installRoot, 'var/lib/debz'));
  assert.equal(failureOutputs.size, 0);
  const failedVerification = await defaultServices.runDebz(
    localCli, buildTransactionResultArguments(failureInputs),
    elevated ? '/usr/bin/sudo' : undefined,
  );
  assert.equal(failedVerification.code, 7);
  assert.equal(failedVerification.stdout, '');
  assert.match(failedVerification.stderr, /TransactionNotSuccessful/u);
  const wrongBackend = await inputsFor({
    ...environment, DEBZ_INSTALL_LOCK_INPUT: path.join(workspace, 'legacy.lock.json'),
  }, runnerArchitecture, 'cross-backend', 'keep-existing');
  const statusPath = path.join(wrongBackend.installRoot, 'var/lib/dpkg/status');
  const before = await readFile(statusPath);
  const refusedOutputs = new Map<string, string>();
  await assert.rejects(runNative(wrongBackend, refusedOutputs));
  assert.equal(refusedOutputs.size, 0);
  assert.deepEqual(await readFile(statusPath), before);
  const documents = observed.map((source) => JSON.parse(source));
  const receipts = documents.filter((document) => document.evidence)
    .map((document) => document.evidence.receipt.transaction_digest_sha256);
  assert.equal(receipts.length, 5);
  assert.equal(new Set(receipts).size, receipts.length);
  const observations = path.join(workspace, 'observed-native-results.json');
  await writeFile(observations, JSON.stringify(documents));
  await promisify(execFile)('/usr/bin/python3', ['-c', `
import json, pathlib, sys
import jsonschema
schemas = pathlib.Path(sys.argv[1]) / "schema"
for document in json.loads(pathlib.Path(sys.argv[2]).read_text()):
    name = "native-install-result-v1.json" if "evidence" in document else "native-install-capability-v1.json"
    jsonschema.Draft202012Validator(json.loads((schemas / name).read_text())).validate(document)
`, path.resolve(actionPath, '../..'), observations], {
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1', TMPDIR: temporary },
    timeout: 30_000, maxBuffer: 1024 * 1024,
  });
});

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
  observe?: (args: string[], result: CommandExecution) => void,
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
    async runDebz(executable, args, sudo, maximum) {
      const result = await defaultServices.runDebz(executable, args, sudo, maximum);
      observe?.(args, result);
      return result;
    },
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
