import * as core from '@actions/core';
import path from 'node:path';

import {
  DebzInstallExitError,
  InstallActionError,
  errorMessage,
} from './errors.js';
import {
  captureDirectoryIdentity,
  captureFileIdentity,
  captureOptionalFileIdentity,
  requireFreshResult,
  verifyDirectoryIdentity,
  verifyFileIdentity,
  verifyOptionalFileIdentity,
  type DirectoryIdentity,
  type FileIdentity,
  type OptionalFileIdentity,
} from './identity.js';
import {
  prepareDirectories,
  readInputs,
  type Inputs,
} from './inputs.js';
import {
  buildInstallArguments,
  buildTransactionResultArguments,
  failureDiagnostic,
  transactionResultPath,
  validateInstallCommandResult,
  validateTransactionSummary,
  validateVersionOutput,
} from './runner.js';
import {
  BundledActionRunner,
  findSudo,
  runDebz,
  type CommandExecution,
  type DownloadOutputs,
  type SetupOutputs,
} from './subprocess.js';

export interface ActionIO {
  info(message: string): void;
  error(message: string): void;
  setOutput(name: string, value: string): void;
}

export interface CompositionRunner {
  setup(): Promise<SetupOutputs>;
  download(debzPath: string): Promise<DownloadOutputs>;
  saveSetupCache(): Promise<void>;
  cleanup(): Promise<void>;
}

export interface Services {
  prepareDirectories(inputs: Inputs): Promise<void>;
  captureFile(filename: string): Promise<FileIdentity>;
  verifyFile(identity: FileIdentity): Promise<void>;
  captureDirectory(directory: string): Promise<DirectoryIdentity>;
  verifyDirectory(identity: DirectoryIdentity): Promise<void>;
  captureOptionalFile(filename: string): Promise<OptionalFileIdentity>;
  requireFreshResult(identity: OptionalFileIdentity): Promise<OptionalFileIdentity>;
  verifyOptionalFile(identity: OptionalFileIdentity): Promise<void>;
  runDebz(
    executable: string,
    arguments_: string[],
    sudoPath?: string,
    maximumOutputBytes?: number,
  ): Promise<CommandExecution>;
  findSudo(): Promise<string>;
  createComposition(inputs: Inputs): CompositionRunner;
}

export const defaultIO: ActionIO = {
  info: (message) => core.info(message),
  error: (message) => core.error(message),
  setOutput: (name, value) => core.setOutput(name, value),
};

export const defaultServices: Services = {
  prepareDirectories,
  captureFile: captureFileIdentity,
  verifyFile: verifyFileIdentity,
  captureDirectory: captureDirectoryIdentity,
  verifyDirectory: verifyDirectoryIdentity,
  captureOptionalFile: captureOptionalFileIdentity,
  requireFreshResult,
  verifyOptionalFile: verifyOptionalFileIdentity,
  runDebz,
  findSudo,
  createComposition: (inputs) => new BundledActionRunner(inputs),
};

export async function runAction(
  inputs: Inputs,
  io: ActionIO = defaultIO,
  services: Services = defaultServices,
): Promise<void> {
  const protectedFiles = await Promise.all(
    [
      inputs.lockInput,
      ...inputs.sources,
      ...inputs.configs,
      ...inputs.keyrings,
      ...(inputs.credentialReference === undefined
        ? []
        : [inputs.credentialReference]),
    ].map(async (filename) => await services.captureFile(filename)),
  );
  await services.prepareDirectories(inputs);
  const mutableDirectories = await Promise.all(
    [inputs.installRoot, inputs.statePath, inputs.cacheRoot].map(
      async (directory) => await services.captureDirectory(directory),
    ),
  );
  const composition = services.createComposition(inputs);
  let failure: unknown;
  let outputs:
    | {
        executablePath: string;
        setup: SetupOutputs;
        download: DownloadOutputs;
        resultPath: string;
        installedCount: number;
      }
    | undefined;
  try {
    const setup = await composition.setup();
    if (!isStrictChild(inputs.runnerTemp, setup.debzPath)) {
      throw new InstallActionError(
        'setup action returned a debz path outside RUNNER_TEMP',
      );
    }
    const executable = await services.captureFile(setup.debzPath);
    const directVersion = await services.runDebz(executable.path, ['version']);
    if (directVersion.code !== 0) {
      throw new InstallActionError(
        'the verified debz executable failed its version command',
      );
    }
    validateVersionOutput(
      directVersion.stdout,
      directVersion.stderr,
      setup.debzVersion,
    );

    const sudoPath = inputs.useSudo ? await services.findSudo() : undefined;
    if (sudoPath !== undefined) {
      const elevatedVersion = await services.runDebz(
        executable.path,
        ['version'],
        sudoPath,
      );
      if (elevatedVersion.code !== 0) {
        throw new InstallActionError(
          'use-sudo requires noninteractive sudo access to the exact verified debz executable',
        );
      }
      validateVersionOutput(
        elevatedVersion.stdout,
        elevatedVersion.stderr,
        setup.debzVersion,
      );
    }

    await verifyIdentities(
      protectedFiles,
      mutableDirectories,
      executable,
      services,
    );
    const download = await composition.download(executable.path);
    await verifyIdentities(
      protectedFiles,
      mutableDirectories,
      executable,
      services,
    );

    const resultPath = transactionResultPath(inputs);
    const priorResult = await services.captureOptionalFile(resultPath);
    const execution = await services.runDebz(
      executable.path,
      buildInstallArguments(inputs),
      sudoPath,
      32 * 1024 * 1024,
    );
    if (execution.code !== 0) {
      throw new DebzInstallExitError(
        execution.code,
        inputs.statePath,
        failureDiagnostic(execution.stdout),
      );
    }
    if (execution.stderr.length !== 0) {
      throw new InstallActionError('debz wrote unexpected stderr on success');
    }
    validateInstallCommandResult(execution.stdout);
    await verifyIdentities(
      protectedFiles,
      mutableDirectories,
      executable,
      services,
    );
    const freshResult = await services.requireFreshResult(priorResult);

    const summaryExecution = await services.runDebz(
      executable.path,
      buildTransactionResultArguments(inputs),
      sudoPath,
      64 * 1024,
    );
    if (summaryExecution.code !== 0 || summaryExecution.stderr.length !== 0) {
      throw new InstallActionError(
        'the canonical transaction result could not be verified',
      );
    }
    const summary = validateTransactionSummary(
      summaryExecution.stdout,
      inputs,
      download.lockDigest,
    );
    if (
      summary.installedCount !==
      download.downloadedCount + download.reusedCount
    ) {
      throw new InstallActionError(
        'package preparation and final transaction disagree on closure size',
      );
    }
    await services.verifyOptionalFile(freshResult);
    await verifyIdentities(
      protectedFiles,
      mutableDirectories,
      executable,
      services,
    );
    await composition.saveSetupCache();
    await services.verifyFile(executable);
    outputs = {
      executablePath: executable.path,
      setup,
      download,
      resultPath,
      installedCount: summary.installedCount,
    };
  } catch (error) {
    failure = error;
  }
  try {
    await composition.cleanup();
  } catch (error) {
    if (failure === undefined) failure = error;
  }
  if (failure !== undefined) throw failure;
  if (outputs === undefined) {
    throw new InstallActionError(
      'install action completed without verified transaction outputs',
    );
  }

  io.setOutput('debz-path', outputs.executablePath);
  io.setOutput('debz-version', outputs.setup.debzVersion);
  io.setOutput('target', outputs.setup.target);
  io.setOutput('cli-cache-hit', outputs.setup.cacheHit ? 'true' : 'false');
  io.setOutput(
    'package-cache-hit',
    outputs.download.cacheHit ? 'true' : 'false',
  );
  io.setOutput('package-cache-path', outputs.download.cachePath);
  io.setOutput('package-cache-root', outputs.download.cacheRoot);
  io.setOutput('lock-digest', outputs.download.lockDigest);
  io.setOutput('downloaded-count', String(outputs.download.downloadedCount));
  io.setOutput('reused-count', String(outputs.download.reusedCount));
  io.setOutput('transaction-result', outputs.resultPath);
  io.setOutput('provenance', outputs.resultPath);
  io.setOutput('installed-count', String(outputs.installedCount));
}

async function verifyIdentities(
  protectedFiles: FileIdentity[],
  mutableDirectories: DirectoryIdentity[],
  executable: FileIdentity,
  services: Services,
): Promise<void> {
  await Promise.all([
    ...protectedFiles.map(async (identity) => await services.verifyFile(identity)),
    ...mutableDirectories.map(
      async (identity) => await services.verifyDirectory(identity),
    ),
    services.verifyFile(executable),
  ]);
}

function isStrictChild(parent: string, child: string): boolean {
  const relative = path.relative(path.resolve(parent), path.resolve(child));
  return (
    relative.length > 0 &&
    !relative.startsWith(`..${path.sep}`) &&
    relative !== '..' &&
    !path.isAbsolute(relative)
  );
}

export function requireNode24(version: string): void {
  const major = Number(version.split('.', 1)[0]);
  if (!Number.isInteger(major) || major < 24) {
    throw new InstallActionError(
      `install action requires the maintained Node 24 runtime, received ${version}`,
    );
  }
}

export async function runMain(): Promise<void> {
  try {
    requireNode24(process.versions.node);
    const inputs = await readInputs();
    if (inputs.token !== undefined) core.setSecret(inputs.token);
    delete process.env.INPUT_TOKEN;
    delete process.env.DEBZ_INSTALL_TOKEN;
    delete process.env.INPUT_PROXY;
    delete process.env.DEBZ_INSTALL_PROXY;
    delete process.env['INPUT_CREDENTIAL-REFERENCE'];
    delete process.env.DEBZ_INSTALL_CREDENTIAL_REFERENCE;
    process.umask(0o077);
    await runAction(inputs);
  } catch (error) {
    if (error instanceof DebzInstallExitError) {
      if (error.diagnostic !== undefined) {
        core.error(`debz install failed: ${error.diagnostic}`);
      } else {
        core.error(error.message);
      }
      core.info(
        `Transaction state was preserved at ${error.statePath}; recovery is explicit and must use the same verified CLI, root, state, lock, repository, architecture, and policy inputs.`,
      );
      process.exitCode = error.exitCode;
      return;
    }
    core.setFailed(errorMessage(error));
  }
}
