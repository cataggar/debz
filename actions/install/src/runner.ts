import path from 'node:path';

import { InstallActionError } from './errors.js';
import type { Inputs } from './inputs.js';

const commandKeys = [
  'schema',
  'api_version',
  'operation',
  'exit_status',
  'changed',
  'summary',
  'items',
  'diagnostics',
];
const summaryKeys = [
  'schema',
  'api_version',
  'transaction_schema',
  'transaction_schema_version',
  'target_architecture',
  'request_sha256',
  'solver_policy_sha256',
  'lock_sha256',
  'transaction_digest_sha256',
  'package_count',
  'outcome',
  'final_verification_status',
  'lock_evidence',
];
const itemKeys = ['package', 'version', 'architecture', 'detail'];
const hex64 = /^[0-9a-f]{64}$/u;

export interface TransactionSummary {
  lockDigest: string;
  transactionDigest: string;
  installedCount: number;
}

export function buildInstallArguments(inputs: Inputs): string[] {
  const arguments_ = [
    'install',
    '--install-root',
    inputs.installRoot,
    '--cache-path',
    inputs.cacheRoot,
    '--state-path',
    inputs.statePath,
    '--architecture',
    inputs.architecture,
    '--lock-input',
    inputs.lockInput,
    '--repository-policy',
    inputs.repositoryPolicy,
    '--lock-wait-ms',
    String(inputs.lockWaitMs),
    '--cache-only',
    '--assume-yes',
    '--noninteractive',
    '--conffile',
    inputs.conffile,
  ];
  for (const source of inputs.sources) arguments_.push('--source', source);
  for (const config of inputs.configs) arguments_.push('--config', config);
  for (const keyring of inputs.keyrings) arguments_.push('--keyring', keyring);
  for (const architecture of inputs.foreignArchitectures) {
    arguments_.push('--foreign-architecture', architecture);
  }
  if (inputs.defaultRelease !== undefined) {
    arguments_.push('--default-release', inputs.defaultRelease);
  }
  if (inputs.recommends) arguments_.push('--recommends');
  if (inputs.allowDowngrade) arguments_.push('--allow-downgrade');
  if (inputs.proxy !== undefined) arguments_.push('--proxy', inputs.proxy);
  if (inputs.credentialReference !== undefined) {
    arguments_.push('--credential-reference', inputs.credentialReference);
  }
  if (inputs.deadlineMs !== undefined) {
    arguments_.push('--deadline-ms', String(inputs.deadlineMs));
  }
  for (const force of inputs.forces) arguments_.push('--force', force);
  arguments_.push('--json', inputs.package);
  return arguments_;
}

export function buildTransactionResultArguments(inputs: Inputs): string[] {
  return [
    'transaction-result',
    'verify',
    '--state-path',
    inputs.statePath,
    '--lock-input',
    inputs.lockInput,
    '--architecture',
    inputs.architecture,
    '--json',
  ];
}

export function validateVersionOutput(
  stdout: string,
  stderr: string,
  expectedTag: string,
): void {
  if (stderr.length !== 0 || stdout !== `${expectedTag.slice(1)}\n`) {
    throw new InstallActionError(
      'the verified debz executable reported an unexpected version',
    );
  }
}

export function validateInstallCommandResult(output: string): void {
  const document = parseCanonicalLine(
    output,
    32 * 1024 * 1024,
    'install command result',
  );
  exactKeys(document, commandKeys, 'install command result');
  literal(document.schema, 'io.github.cataggar.debz.command.v1', 'schema');
  literal(document.api_version, 1, 'api_version');
  literal(document.operation, 'install', 'operation');
  literal(document.exit_status, 0, 'exit_status');
  if (typeof document.changed !== 'boolean') {
    throw new InstallActionError("debz JSON field 'changed' is invalid");
  }
  boundedString(document.summary, 'summary', 4096);
  if (!Array.isArray(document.items) || document.items.length > 1_000_000) {
    throw new InstallActionError("debz JSON field 'items' is invalid");
  }
  for (const value of document.items) {
    const item = record(value, 'install item');
    exactKeys(item, itemKeys, 'install item');
    boundedString(item.package, 'items.package', 255);
    optionalString(item.version, 'items.version', 4096);
    optionalString(item.architecture, 'items.architecture', 64);
    optionalString(item.detail, 'items.detail', 4096);
  }
  if (!Array.isArray(document.diagnostics) || document.diagnostics.length !== 0) {
    throw new InstallActionError(
      'successful debz install result contains diagnostics',
    );
  }
}

export function failureDiagnostic(output: string): string | undefined {
  try {
    const document = parseCanonicalLine(output, 1024 * 1024, 'install failure');
    exactKeys(document, commandKeys, 'install failure');
    if (
      document.schema !== 'io.github.cataggar.debz.command.v1' ||
      document.api_version !== 1 ||
      document.operation !== 'install' ||
      !Number.isSafeInteger(document.exit_status) ||
      (document.exit_status as number) === 0 ||
      !Array.isArray(document.diagnostics) ||
      document.diagnostics.length !== 1
    ) {
      return undefined;
    }
    const diagnostic = record(document.diagnostics[0], 'diagnostic');
    exactKeys(diagnostic, ['id', 'message'], 'diagnostic');
    const id = boundedString(diagnostic.id, 'diagnostic.id', 128);
    const message = boundedString(
      diagnostic.message,
      'diagnostic.message',
      512,
    );
    return `${id}: ${message}`;
  } catch {
    return undefined;
  }
}

export function validateTransactionSummary(
  output: string,
  inputs: Inputs,
  expectedLockDigest: string,
): TransactionSummary {
  const document = parseCanonicalLine(
    output,
    64 * 1024,
    'transaction-result summary',
  );
  exactKeys(document, summaryKeys, 'transaction-result summary');
  literal(
    document.schema,
    'io.github.cataggar.debz.transaction-result-summary.v1',
    'schema',
  );
  literal(document.api_version, 1, 'api_version');
  literal(
    document.transaction_schema,
    'https://debz.dev/schema/transaction-result-v1',
    'transaction_schema',
  );
  literal(document.transaction_schema_version, 1, 'transaction_schema_version');
  literal(document.target_architecture, inputs.architecture, 'target_architecture');
  literal(document.lock_sha256, expectedLockDigest, 'lock_sha256');
  literal(document.outcome, 'succeeded', 'outcome');
  literal(
    document.final_verification_status,
    'exact_match',
    'final_verification_status',
  );
  literal(document.lock_evidence, 'exact_match', 'lock_evidence');
  for (const name of [
    'request_sha256',
    'solver_policy_sha256',
    'transaction_digest_sha256',
  ]) {
    if (typeof document[name] !== 'string' || !hex64.test(document[name])) {
      throw new InstallActionError(`transaction summary field '${name}' is invalid`);
    }
  }
  const packageCount = document.package_count;
  if (!Number.isSafeInteger(packageCount) || (packageCount as number) < 1) {
    throw new InstallActionError(
      "transaction summary field 'package_count' is invalid",
    );
  }
  return {
    lockDigest: expectedLockDigest,
    transactionDigest: document.transaction_digest_sha256 as string,
    installedCount: packageCount as number,
  };
}

export function transactionResultPath(inputs: Inputs): string {
  return path.join(inputs.statePath, 'transaction-result.json');
}

function parseCanonicalLine(
  output: string,
  maximumBytes: number,
  label: string,
): Record<string, unknown> {
  if (
    Buffer.byteLength(output) > maximumBytes ||
    output.includes('\r') ||
    !output.endsWith('\n') ||
    output.slice(0, -1).includes('\n')
  ) {
    throw new InstallActionError(`debz ${label} is not one bounded canonical line`);
  }
  const body = output.slice(0, -1);
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch {
    throw new InstallActionError(`debz ${label} is malformed JSON`);
  }
  if (JSON.stringify(value) !== body) {
    throw new InstallActionError(`debz ${label} is not canonical JSON`);
  }
  return record(value, label);
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new InstallActionError(`debz ${label} is not an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  object: Record<string, unknown>,
  expected: string[],
  label: string,
): void {
  const actual = Object.keys(object);
  if (
    actual.length !== expected.length ||
    actual.some((name, index) => name !== expected[index])
  ) {
    throw new InstallActionError(`debz ${label} has an unsupported field set`);
  }
}

function literal<T extends string | number | boolean>(
  value: unknown,
  expected: T,
  name: string,
): asserts value is T {
  if (value !== expected) {
    throw new InstallActionError(`debz JSON field '${name}' has an unexpected value`);
  }
}

function boundedString(value: unknown, name: string, maximum: number): string {
  if (
    typeof value !== 'string' ||
    value.length > maximum ||
    value.includes('\0') ||
    value.includes('\r') ||
    value.includes('\n')
  ) {
    throw new InstallActionError(`debz JSON field '${name}' is invalid`);
  }
  return value;
}

function optionalString(value: unknown, name: string, maximum: number): void {
  if (value !== null) boundedString(value, name, maximum);
}
