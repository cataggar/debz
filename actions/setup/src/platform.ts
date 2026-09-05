import { SetupError } from './errors.js';

export type Target = 'linux-x64' | 'linux-arm64';

export interface Platform {
  target: Target;
  abi: 'musl-static';
  runnerArch: 'X64' | 'ARM64';
  processArch: 'x64' | 'arm64';
}

export function normalizePlatform(
  runnerOS: string,
  runnerArch: string,
  processPlatform = process.platform,
  processArch = process.arch,
): Platform {
  if (runnerOS !== 'Linux' || processPlatform !== 'linux') {
    throw new SetupError(
      `unsupported platform: RUNNER_OS=${runnerOS || '<unset>'}, process.platform=${processPlatform}; only Linux is supported`,
    );
  }

  const mappings: Record<string, { target: Target; processArch: 'x64' | 'arm64' }> = {
    X64: { target: 'linux-x64', processArch: 'x64' },
    ARM64: { target: 'linux-arm64', processArch: 'arm64' },
  };
  const mapping = mappings[runnerArch];
  if (!mapping) {
    throw new SetupError(
      `unsupported architecture: RUNNER_ARCH=${runnerArch || '<unset>'}; only X64 and ARM64 are supported`,
    );
  }
  if (processArch !== mapping.processArch) {
    throw new SetupError(
      `runner architecture mismatch: RUNNER_ARCH=${runnerArch}, process.arch=${processArch}`,
    );
  }
  return {
    target: mapping.target,
    abi: 'musl-static',
    runnerArch: runnerArch as 'X64' | 'ARM64',
    processArch: mapping.processArch,
  };
}
