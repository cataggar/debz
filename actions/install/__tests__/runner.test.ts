import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildInstallArguments,
  buildTransactionResultArguments,
  failureDiagnostic,
  validateInstallCommandResult,
  validateTransactionSummary,
  validateNativeInstallResult,
} from '../src/runner.js';
import {
  commandResult,
  fixtureInputs,
  transactionSummary,
  nativeInstallResult,
  nativeTransactionSummary,
} from './helpers.js';

test('builds one structural cache-only install argv with closed-set force values', () => {
  const inputs = fixtureInputs('/work');
  inputs.forces = [
    'depends',
    'depends_version',
    'break_replaces',
    'overwrite',
    'overwrite_dir',
    'remove_reinstreq',
  ];
  const arguments_ = buildInstallArguments(inputs);
  assert.equal(arguments_[0], 'install');
  assert.equal(arguments_.filter((value) => value === '--cache-only').length, 1);
  assert.equal(arguments_.filter((value) => value === '--force').length, 6);
  for (const force of inputs.forces) assert.equal(arguments_.includes(force), true);
  assert.equal(arguments_.at(-1), 'scenario-main');
  assert.equal(arguments_.includes('--assume-yes'), true);
  assert.equal(arguments_.includes('--noninteractive'), true);
  assert.equal(arguments_.includes('/bin/sh'), false);
  assert.equal(arguments_.includes('--transaction-backend'), false);
  assert.equal(arguments_.includes('--native-result'), false);
});

test('native result formats are explicit, bounded, and distinct from legacy evidence', () => {
  const inputs = fixtureInputs('/work');
  inputs.transactionBackend = 'native';
  assert.ok(buildInstallArguments(inputs).includes('--native-result'));
  assert.ok(buildTransactionResultArguments(inputs).includes('--install-root'));
  assert.equal(buildTransactionResultArguments(inputs).includes('--state-path'), false);
  assert.throws(() => validateNativeInstallResult(commandResult(), inputs, 'a'.repeat(64)));
  const result = validateNativeInstallResult(nativeInstallResult(inputs), inputs, 'a'.repeat(64));
  assert.throws(() => validateTransactionSummary(transactionSummary(), inputs, 'a'.repeat(64), result));
  const legacy = { ...inputs, transactionBackend: 'legacy_dpkg' as const };
  assert.throws(() => validateTransactionSummary(nativeTransactionSummary(inputs), legacy, 'a'.repeat(64)));
  assert.equal(validateNativeInstallResult(nativeInstallResult(inputs, false, 0), inputs, 'a'.repeat(64)).installedCount, 0);
  for (const count of [-1, 0.5, 100001]) {
    assert.throws(() => validateNativeInstallResult(nativeInstallResult(inputs, false, count), inputs, 'a'.repeat(64)), /package_count/u);
  }
  const stale = JSON.parse(nativeInstallResult(inputs));
  stale.command.changed = false;
  assert.throws(() => validateNativeInstallResult(`${JSON.stringify(stale)}\n`, inputs, 'a'.repeat(64)), /must not claim/u);
  stale.command.changed = true;
  stale.evidence.receipt = null;
  assert.throws(() => validateNativeInstallResult(`${JSON.stringify(stale)}\n`, inputs, 'a'.repeat(64)), /not an object/u);
});

test('accepts only canonical successful command and transaction summaries', () => {
  const inputs = fixtureInputs('/work');
  validateInstallCommandResult(commandResult());
  const summary = validateTransactionSummary(
    transactionSummary(),
    inputs,
    'a'.repeat(64),
  );
  assert.equal(summary.installedCount, 4);

  assert.throws(
    () =>
      validateTransactionSummary(
        `${transactionSummary().trim()} \n`,
        inputs,
        'a'.repeat(64),
      ),
    /not canonical/u,
  );
  assert.throws(
    () =>
      validateTransactionSummary(
        transactionSummary('e'.repeat(64)),
        inputs,
        'a'.repeat(64),
      ),
    /lock_sha256/u,
  );
});

test('extracts only bounded structured failure diagnostics', () => {
  assert.equal(
    failureDiagnostic(commandResult(7)),
    'transaction_failed: fixture failure',
  );
  assert.equal(failureDiagnostic('not json\n'), undefined);
});
