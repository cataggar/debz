import assert from 'node:assert/strict';
import {
  existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { arch } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { after, mock, test } from 'node:test';
import {
  auditWorkflow, bindSource, inventory, main, planRows, runSelector,
  selectors, selectTargets,
} from './tooling-fleet.mjs';

const root = resolve(import.meta.dirname, '..');
const workflow = readFileSync(join(root, '.github/workflows/tooling.yml'), 'utf8');
const scratch = join(root, '.cache', `tooling-fleet-tests-${process.pid}`);
mkdirSync(scratch, { recursive: true });
after(() => rmSync(scratch, { recursive: true, force: true }));
const available = new Set(Object.entries(selectors).flatMap(([test, builds]) => [test, ...builds]));
let fixtureNumber = 0;

function git(directory, args) {
  const result = spawnSync('git', args, { cwd: directory, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function fixture() {
  const directory = join(scratch, `source-${++fixtureNumber}`);
  mkdirSync(join(directory, '.github/workflows'), { recursive: true });
  writeFileSync(join(directory, '.github/workflows/tooling.yml'), workflow);
  writeFileSync(join(directory, 'build.zig'), [...available].map(name => `b.step("${name}", "fixture");`).join('\n'));
  writeFileSync(join(directory, '.gitignore'), '/.cache/\n/zig-out/\n');
  git(directory, ['init', '--quiet', '--initial-branch=main']);
  git(directory, ['add', '.']);
  git(directory, ['-c', 'user.name=Tooling test', '-c', 'user.email=tooling-test@example.invalid',
    '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Independent dispatch test fixture']);
  const env = {
    ...process.env,
    GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REPOSITORY: 'cataggar/debz',
    GITHUB_REF: 'refs/heads/main',
    GITHUB_SHA: git(directory, ['rev-parse', 'HEAD']),
    SOURCE_SHA: git(directory, ['rev-parse', 'HEAD']),
    SOURCE_TREE: git(directory, ['rev-parse', 'HEAD^{tree}']),
    SELECTORS: 'test-integration-repository', SELECTOR: 'test-integration-repository',
    ARCHITECTURE: arch() === 'arm64' ? 'arm64' : 'amd64', OPTIMIZE: 'Debug',
    GITHUB_RUN_ID: '12', GITHUB_RUN_ATTEMPT: '1',
    GITHUB_ACTIONS: 'false',
    GITHUB_OUTPUT: join(directory, '.cache', 'actions-output'),
  };
  mkdirSync(join(directory, '.cache', 'bin'), { recursive: true });
  const fakeZig = `#!${process.execPath}
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const args = process.argv.slice(2);
if (args[0] === 'version') { console.log(process.env.FAKE_ZIG_VERSION ?? '0.16.0'); }
else if (args.includes('--help')) {
  console.log(${JSON.stringify([...available].map(name => `  ${name} fixture`).join('\n'))});
} else {
  appendFileSync('.cache/build-calls.jsonl', JSON.stringify({
    args, local: process.env.ZIG_LOCAL_CACHE_DIR, global: process.env.ZIG_GLOBAL_CACHE_DIR,
    scratch: process.env.TMPDIR, path: process.env.PATH
  }) + '\\n');
  if (process.env.FAKE_ZIG_FAIL === '1') process.exit(17);
  const prefix = args[args.indexOf('--prefix') + 1];
  mkdirSync(join(prefix, 'bin'), { recursive: true });
  writeFileSync(join(prefix, 'bin', 'actual-fixture-tool'), '#!/bin/sh\\nexit 0\\n', {mode: 0o755});
  if (args.includes('test-integration-repository') && process.env.FAKE_ZIG_DIRTY === '1') {
    appendFileSync('build.zig', '\\n// changed during build\\n');
  }
}
`;
  writeFileSync(join(directory, '.cache/bin/zig'), fakeZig, { mode: 0o755 });
  env.PATH = `${join(directory, '.cache/bin')}:${process.env.PATH}`;
  return { directory, env };
}

test('both architectures and modes schedule distinct exact selector rows without aliases', () => {
  const selected = selectTargets('test-integration-repository test-disposable-runtime', available);
  const rows = planRows(selected, 'both', 'both').include;
  assert.equal(rows.length, 8);
  assert.equal(new Set(rows.map(row => `${row.selector}/${row.architecture}/${row.optimize}`)).size, 8);
  for (const row of rows) {
    assert.deepEqual(JSON.parse(row.labels),
      ['self-hosted', 'Linux', row.architecture === 'amd64' ? 'X64' : 'ARM64', 'ubuntu2604']);
  }
  assert.equal(planRows(selected, 'arm64', 'ReleaseSafe').include.length, 2);
});

test('unknown, privileged, duplicate, injected and actually absent targets refuse before scheduling', () => {
  for (const value of ['', 'test', 'test-release', 'security-audit', 'install',
    'test-real-snapshot-reference-protected', 'test-real-snapshot-reference-launcher-root',
    'test-integration-repository; sudo true', 'test-integration-repository\ninstall',
    'test-integration-repository test-integration-repository']) {
    assert.throws(() => selectTargets(value, available), undefined, value);
  }
  const missingProducer = new Set(available);
  missingProducer.delete('build-integration-repository');
  assert.throws(() => selectTargets('test-integration-repository', missingProducer), /no actual build selector/);
  assert.throws(() => planRows(['test-integration-repository'], 'x86', 'both'), /architecture/);
  assert.throws(() => planRows(['test-integration-repository'], 'both', 'ReleaseFast'), /mode/);
});

test('workflow guards scope actual compiler, consumer, source planner and paid route', () => {
  auditWorkflow(workflow);
  const mutations = [
    ["github.event_name == 'workflow_dispatch'", 'true'],
    ["github.repository == 'cataggar/debz'", 'true'],
    ["startsWith(github.ref, 'refs/heads/')", 'true'],
    ['    runs-on: ubuntu-24.04', '    runs-on: [self-hosted, Linux, X64, ubuntu2604]'],
    ['    needs: bind-source', '    needs: []'],
    ['    runs-on: ${{ fromJSON(matrix.labels) }}', '    runs-on: ubuntu-24.04'],
    ['          ref: ${{ inputs.source_sha }}', '          ref: main'],
    ['persist-credentials: false', 'persist-credentials: true'],
    ['attestations: read', 'attestations: write'],
    ['cataggar/zig@v0.16.0', 'cataggar/zig@v0.15.0'],
    ['RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U', 'unreviewed-key'],
    ['run: test "$(zig version)" = 0.16.0', 'run: echo compiler-is-fine'],
    ['node tools/tooling-fleet.mjs run', 'node tools/tooling-fleet.mjs plan'],
    ['node --test tools/test-tooling-fleet.mjs', 'echo tests-skipped'],
    ['SELECTOR: ${{ matrix.selector }}', 'SELECTOR: install'],
    ['SOURCE_TREE: ${{ inputs.source_tree }}', 'SOURCE_TREE: ignored'],
    ['ARCHITECTURE: ${{ matrix.architecture }}', 'ARCHITECTURE: amd64'],
    ['OPTIMIZE: ${{ matrix.optimize }}', 'OPTIMIZE: Debug'],
    ['actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020', 'actions/setup-node@v4'],
  ];
  for (const [before, after] of mutations) {
    assert.ok(workflow.includes(before), before);
    const poisoned = `${workflow.replace(before, after)}\n# ${before}\n`;
    assert.throws(() => auditWorkflow(poisoned), undefined, before);
  }
  for (const extra of [
    '  pull_request:', '  pull_request_target:', '        continue-on-error: true',
    '        run: sudo true', '        uses: actions/cache@0123456789012345678901234567890123456789',
    '        env: ${{ secrets.OTHER }}',
  ]) assert.throws(() => auditWorkflow(`${workflow}\n${extra}\n`), undefined, extra);
  const compiler = workflow.indexOf('      - name: Install Zig via ghr');
  const check = workflow.indexOf('      - name: Validate Zig version');
  const run = workflow.indexOf('      - name: Run bound unprivileged tooling selector');
  const reordered = workflow.slice(0, compiler) + workflow.slice(check, run)
    + workflow.slice(compiler, check) + workflow.slice(run);
  assert.throws(() => auditWorkflow(reordered), /follow verified compiler/);
});

test('source binding refuses fork, PR, other SHA/tree and dirty checkout contexts', () => {
  const { directory, env } = fixture();
  bindSource(env, directory);
  for (const mutation of [
    { GITHUB_EVENT_NAME: 'pull_request' }, { GITHUB_REPOSITORY: 'fork/debz' },
    { GITHUB_REF: 'refs/pull/1/merge' }, { SOURCE_SHA: 'a'.repeat(40) },
    { SOURCE_TREE: 'b'.repeat(40) }, { SOURCE_SHA: 'main' },
  ]) assert.throws(() => bindSource({ ...env, ...mutation }, directory));
  writeFileSync(join(directory, 'build.zig'), 'dirty source');
  assert.throws(() => bindSource(env, directory), /dirty/);
});

test('real planner emits machine-readable bound matrices and refuses unavailable ports', () => {
  const { directory, env } = fixture();
  main('plan', { ...env, ARCHITECTURE: 'both', OPTIMIZE: 'both' }, directory);
  const result = readFileSync(env.GITHUB_OUTPUT, 'utf8');
  assert.equal(JSON.parse(result.slice('matrix='.length)).include.length, 4);
  const original = readFileSync(join(directory, 'build.zig'), 'utf8');
  writeFileSync(join(directory, 'build.zig'), original.replace(
    'b.step("build-reference-order", "fixture");', ''));
  git(directory, ['add', '.']);
  git(directory, ['-c', 'user.name=Tooling test', '-c', 'user.email=tooling-test@example.invalid',
    '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Port absent']);
  const source = git(directory, ['rev-parse', 'HEAD']);
  assert.throws(() => main('plan', { ...env, SOURCE_SHA: source, GITHUB_SHA: source,
    SOURCE_TREE: git(directory, ['rev-parse', 'HEAD^{tree}']),
    SELECTORS: 'test-real-snapshot-reference-order' }, directory), /no actual build selector/);
});

test('installed inventory enumerates actual tools and refuses links instead of guessing names or counts', () => {
  const prefix = join(scratch, 'inventory');
  mkdirSync(join(prefix, 'bin'), { recursive: true });
  writeFileSync(join(prefix, 'bin/new-consumer'), 'real fixture', { mode: 0o755 });
  assert.equal(inventory(prefix)[0].name, 'new-consumer');
  symlinkSync('new-consumer', join(prefix, 'bin/unsafe-tool'));
  assert.throws(() => inventory(prefix), /regular executable/);
});

test('paid execution refuses root before creating caches or launching the compiler', () => {
  const { directory, env } = fixture();
  const uid = mock.method(process, 'getuid', () => 0);
  try {
    assert.throws(() => runSelector(env, directory), /refuses root/);
    assert.ok(!existsSync(join(directory, '.cache/tooling-fleet')));
    assert.ok(!existsSync(join(directory, '.cache/build-calls.jsonl')));
  } finally {
    uid.mock.restore();
  }
});

test('actual executor binds compiler, fresh caches, installed/custom prefixes and exact selected tests', () => {
  const { directory, env } = fixture();
  runSelector(env, directory);
  const calls = readFileSync(join(directory, '.cache/build-calls.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(calls.length, 3);
  assert.equal(calls[0].args[1], 'build-integration-repository');
  assert.equal(calls[1].args[1], 'build-integration-repository');
  assert.equal(calls[2].args[1], env.SELECTOR);
  for (const call of calls) {
    assert.ok(call.args.includes('-Doptimize=Debug'));
    assert.ok(call.args.includes('-j2'));
    assert.ok(call.local.startsWith(join(directory, '.cache/tooling-fleet')));
    assert.ok(call.global.startsWith(join(directory, '.cache/tooling-fleet')));
    assert.ok(call.scratch.startsWith(join(directory, '.cache/tooling-fleet')));
    const poison = call.path.split(':')[0];
    const refusal = spawnSync(join(poison, 'python3'), [], { encoding: 'utf8' });
    assert.equal(refusal.status, 125);
  }
  const reportPath = join(directory, '.cache/tooling-fleet', env.SOURCE_SHA, '12', '1',
    env.ARCHITECTURE, 'Debug', env.SELECTOR, 'reports/binding.json');
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  assert.equal(report.status, 'success');
  assert.equal(report.execution, 'local-validation');
  assert.equal(report.acceptance, false);
  assert.deepEqual(report.normal_install, report.custom_install);
  rmSync(join(directory, 'zig-out'), { recursive: true });
  assert.throws(() => runSelector(env, directory), /EEXIST/);
});

test('compiler mismatch, wrong architecture, build failure and post-build source drift never pass', () => {
  const compiler = fixture();
  assert.throws(() => runSelector({ ...compiler.env, FAKE_ZIG_VERSION: '0.15.0' }, compiler.directory), /compiler version/);
  assert.ok(!existsSync(join(compiler.directory, '.cache/tooling-fleet')));
  assert.throws(() => runSelector({ ...compiler.env,
    ARCHITECTURE: compiler.env.ARCHITECTURE === 'amd64' ? 'arm64' : 'amd64' }, compiler.directory), /architecture mismatch/);
  assert.throws(() => runSelector({ ...compiler.env,
    SELECTOR: 'test-integration-repository test-disposable-runtime' }, compiler.directory), /one exact tooling selector/);
  for (const variable of ['FAKE_ZIG_FAIL', 'FAKE_ZIG_DIRTY']) {
    const { directory, env } = fixture();
    assert.throws(() => runSelector({ ...env, [variable]: '1' }, directory));
    const report = JSON.parse(readFileSync(join(directory, '.cache/tooling-fleet', env.SOURCE_SHA,
      '12', '1', env.ARCHITECTURE, 'Debug', env.SELECTOR, 'reports/binding.json'), 'utf8'));
    assert.equal(report.status, 'failure');
    assert.equal(report.acceptance, false);
  }
});
