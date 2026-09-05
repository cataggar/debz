import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { lt } from 'semver';

import { SetupError, errorMessage } from './errors.js';

const execFileAsync = promisify(execFile);

export type VersionRunner = (executablePath: string, expectedVersion: string) => Promise<void>;

class VersionCommandError extends SetupError {
  constructor(
    message: string,
    readonly exitCode: number | undefined,
    readonly stderrText: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

async function runVersionCommand(
  executablePath: string,
  argument: 'version' | '--version',
): Promise<{ stdout: string; stderr: string }> {
  try {
    return await execFileAsync(executablePath, [argument], {
      encoding: 'utf8',
      env: {
        LANG: 'C',
        LC_ALL: 'C',
      },
      timeout: 10_000,
      maxBuffer: 64 * 1024,
      windowsHide: true,
    });
  } catch (error) {
    const commandError = error as NodeJS.ErrnoException & {
      code?: string | number;
      stderr?: string;
    };
    throw new VersionCommandError(
      `installed debz ${argument} check failed: ${errorMessage(error)}`,
      typeof commandError.code === 'number' ? commandError.code : undefined,
      typeof commandError.stderr === 'string' ? commandError.stderr : '',
      {
        cause: error,
      },
    );
  }
}

function validateVersionOutput(
  result: { stdout: string; stderr: string },
  expectedVersion: string,
): void {
  if (result.stderr !== '') {
    throw new SetupError('installed debz version check wrote unexpected stderr');
  }
  if (
    result.stdout !== `${expectedVersion}\n` &&
    result.stdout !== `${expectedVersion}\r\n`
  ) {
    throw new SetupError(
      `installed debz reported ${JSON.stringify(result.stdout)} instead of ${JSON.stringify(expectedVersion)}`,
    );
  }
}

export const verifyExecutableVersion: VersionRunner = async (executablePath, expectedVersion) => {
  try {
    validateVersionOutput(
      await runVersionCommand(executablePath, 'version'),
      expectedVersion,
    );
    return;
  } catch (error) {
    if (
      !lt(expectedVersion, '0.3.0') ||
      !(error instanceof VersionCommandError) ||
      error.exitCode !== 2 ||
      !error.stderrText.includes("unknown command 'version'")
    ) {
      throw error;
    }
  }
  try {
    validateVersionOutput(
      await runVersionCommand(executablePath, '--version'),
      expectedVersion,
    );
  } catch (error) {
    throw new SetupError(
      `installed debz failed both the version command and the pre-v0.3.0 --version compatibility check: ${errorMessage(error)}`,
      {
      cause: error,
      },
    );
  }
};
