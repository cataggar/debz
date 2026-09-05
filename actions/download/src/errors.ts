export class DownloadActionError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'DownloadActionError';
  }
}

export class CliDiagnosticError extends DownloadActionError {
  constructor(message: string) {
    super(message);
    this.name = 'CliDiagnosticError';
  }
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
