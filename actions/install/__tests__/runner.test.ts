import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildInstallArguments,
  failureDiagnostic,
  validateInstallCommandResult,
  validateTransactionSummary,
} from '../src/runner.js';
import {
  commandResult,
  fixtureInputs,
  transactionSummary,
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
