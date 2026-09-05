import assert from 'node:assert/strict';
import test from 'node:test';

import {
  runAction,
  type ActionIO,
  type CompositionRunner,
  type Services,
} from '../src/action.js';
import { DebzInstallExitError } from '../src/errors.js';
import type {
  DirectoryIdentity,
  FileIdentity,
  OptionalFileIdentity,
} from '../src/identity.js';
import type { Inputs } from '../src/inputs.js';
import type { CommandExecution } from '../src/subprocess.js';
import {
  commandResult,
  fixtureInputs,
  transactionSummary,
} from './helpers.js';

interface Harness {
  inputs: Inputs;
  outputs: Map<string, string>;
  calls: { arguments: string[]; sudo?: string }[];
  cleanup: boolean;
  saved: boolean;
  services: Services;
}

function harness(cacheHit = true): Harness {
  const inputs = fixtureInputs('/work');
  const outputs = new Map<string, string>();
  const calls: { arguments: string[]; sudo?: string }[] = [];
  let cleanup = false;
  let saved = false;
  const fileIdentity: FileIdentity = {
    path: '/work/runner/debz-tools/0.3.0/bin/debz',
    device: 1n,
    inode: 2n,
    size: 3n,
    mode: 0o755n,
    sha256: 'f'.repeat(64),
  };
  const directoryIdentity: DirectoryIdentity = {
    path: '/work/runner/root',
    device: 1n,
    inode: 3n,
  };
  const prior: OptionalFileIdentity = {
    path: '/work/runner/state/transaction-result.json',
    exists: false,
  };
  const composition: CompositionRunner = {
    async setup() {
      return {
        debzPath: fileIdentity.path,
        debzVersion: 'v0.3.0',
        target: 'linux-x64',
        cacheHit: false,
      };
    },
    async download() {
      return {
        cacheHit,
        matchedKey: cacheHit ? `debz-${'a'.repeat(64)}` : '',
        cachePath: inputs.cachePath,
        cacheRoot: inputs.cacheRoot,
        lockDigest: 'a'.repeat(64),
        downloadedCount: cacheHit ? 0 : 4,
        reusedCount: cacheHit ? 4 : 0,
      };
    },
    async saveSetupCache() {
      saved = true;
    },
    async cleanup() {
      cleanup = true;
    },
  };
  const executions: CommandExecution[] = [
    { code: 0, stdout: '0.3.0\n', stderr: '' },
    { code: 0, stdout: commandResult(), stderr: '' },
    { code: 0, stdout: transactionSummary(), stderr: '' },
  ];
  const services: Services = {
    async prepareDirectories() {},
    async captureFile(filename) {
      return { ...fileIdentity, path: filename };
    },
    async verifyFile() {},
    async captureDirectory(directory) {
      return { ...directoryIdentity, path: directory };
    },
    async verifyDirectory() {},
    async captureOptionalFile() {
      return prior;
    },
    async requireFreshResult() {
      return { ...prior, exists: true, device: 1n, inode: 4n };
    },
    async verifyOptionalFile() {},
    async runDebz(_executable, arguments_, sudo) {
      calls.push({ arguments: arguments_, sudo });
      const result = executions.shift();
      assert.ok(result);
      return result;
    },
    async findSudo() {
      return '/usr/bin/sudo';
    },
    createComposition() {
      return composition;
    },
  };
  const io: ActionIO = {
    info() {},
    error() {},
    setOutput(name, value) {
      outputs.set(name, value);
    },
  };
  Object.defineProperties(services, {
    __io: { value: io },
    __state: {
      get: () => ({ cleanup, saved }),
    },
  });
  return {
    inputs,
    outputs,
    calls,
    get cleanup() {
      return cleanup;
    },
    get saved() {
      return saved;
    },
    services,
  };
}

function ioFor(value: Harness): ActionIO {
  return (value.services as Services & { __io: ActionIO }).__io;
}

test('an exact package-cache hit still executes and audits one install', async () => {
  const value = harness(true);
  await runAction(value.inputs, ioFor(value), value.services);
  assert.equal(
    value.calls.filter((call) => call.arguments[0] === 'install').length,
    1,
  );
  assert.equal(value.calls[1].arguments.includes('--cache-only'), true);
  assert.equal(value.outputs.get('package-cache-hit'), 'true');
  assert.equal(value.outputs.get('installed-count'), '4');
  assert.equal(
    value.outputs.get('transaction-result'),
    value.outputs.get('provenance'),
  );
  assert.equal(value.saved, true);
  assert.equal(value.cleanup, true);
});

test('propagates the exact debz exit code and publishes no success outputs', async () => {
  const value = harness(false);
  let invocation = 0;
  value.services.runDebz = async () => {
    invocation += 1;
    if (invocation === 1) return { code: 0, stdout: '0.3.0\n', stderr: '' };
    return { code: 7, stdout: commandResult(7), stderr: '' };
  };
  await assert.rejects(
    runAction(value.inputs, ioFor(value), value.services),
    (error: unknown) =>
      error instanceof DebzInstallExitError && error.exitCode === 7,
  );
  assert.equal(value.outputs.size, 0);
  assert.equal(value.saved, false);
  assert.equal(value.cleanup, true);
});

test('uses explicit sudo for version, install, and result verification only', async () => {
  const value = harness(true);
  value.inputs.useSudo = true;
  const originalRun = value.services.runDebz;
  let invocation = 0;
  value.services.runDebz = async (executable, arguments_, sudo, maximum) => {
    invocation += 1;
    if (invocation === 1) {
      value.calls.push({ arguments: arguments_, sudo });
      return { code: 0, stdout: '0.3.0\n', stderr: '' };
    }
    return await originalRun(executable, arguments_, sudo, maximum);
  };
  await runAction(value.inputs, ioFor(value), value.services);
  assert.equal(value.calls[0].sudo, undefined);
  assert.equal(value.calls.slice(1).every((call) => call.sudo === '/usr/bin/sudo'), true);
});
