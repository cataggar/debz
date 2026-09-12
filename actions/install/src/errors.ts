export class InstallActionError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'InstallActionError';
  }
}

export class DebzInstallExitError extends InstallActionError {
  constructor(
    readonly exitCode: number,
    readonly statePath: string,
    readonly diagnostic?: string,
    readonly transactionBackend: 'legacy_dpkg' | 'native' = 'legacy_dpkg',
  ) {
    super(`debz install failed with exit code ${exitCode}`);
    this.name = 'DebzInstallExitError';
  }
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
