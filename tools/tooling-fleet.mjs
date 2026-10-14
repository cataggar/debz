#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  appendFileSync, existsSync, lstatSync, mkdirSync, readFileSync,
  readdirSync, realpathSync, writeFileSync,
} from 'node:fs';
import { arch } from 'node:os';
import { delimiter, dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// These are pure tooling tests, not root/reference execution or acceptance aliases.
export const selectors = Object.freeze({
  'test-native-outcome': ['build-native-outcome'],
  'test-native-action-empty-lock': ['build-native-action-empty-lock'],
  'test-native-baseline-fixture': ['build-native-baseline-fixture'],
  'test-disposable-runtime': ['build-disposable-runtime'],
  'test-integration-signing': ['build-integration-signing'],
  'test-integration-archive': ['build-integration-archive'],
  'test-native-dpkg-reference': ['build-native-dpkg-reference'],
  'test-debian-stable-readiness': ['build-debian-stable-readiness'],
  'test-integration-repository': ['build-integration-repository'],
  'test-openpgp-fixtures': ['build-openpgp-fixtures'],
  'test-real-snapshot-reference-runtime': ['build-reference-runtime'],
  'test-dpkg-oracle-evidence': ['build-dpkg-oracle-evidence'],
  'test-signed-proc-compare': ['build-signed-proc-compare'],
  'test-vendor-snapshot-tools': ['build-vendor-snapshot-tools'],
  'test-real-snapshot-reference-order': ['build-reference-order'],
  'test-real-snapshot-reference-paths': ['build-reference-paths'],
  'test-real-snapshot-reference-protected-pure': ['build-reference-protected'],
  'test-release-consumers': ['build-release-tool'],
  'test-release-workflow-policy': ['build-release-tool', 'build-release-workflow-policy'],
  'test-native-only-policy': ['build-security-audit'],
});

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function command(program, args, options = {}) {
  const result = spawnSync(program, args, {
    encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, ...options,
  });
  requireValue(!result.error && result.status === 0,
    `${program} ${args.join(' ')} failed: ${result.error?.message ?? result.status}\n${result.stderr ?? ''}`);
  return result.stdout ?? '';
}

function stepNames(build) {
  return new Set([...build.matchAll(/\bb\.step\(\s*"([^"]+)"/g)].map(match => match[1]));
}

export function selectTargets(value, available) {
  requireValue(typeof value === 'string' && /^[a-z0-9 -]+$/.test(value),
    'selectors must be space-separated reviewed test names');
  const selected = value.trim().split(/ +/);
  requireValue(selected.length <= Object.keys(selectors).length && new Set(selected).size === selected.length,
    'duplicate or excessive selectors');
  for (const selector of selected) {
    requireValue(Object.hasOwn(selectors, selector), `unreviewed tooling selector: ${selector}`);
    for (const target of [selector, ...selectors[selector]]) {
      requireValue(available.has(target), `candidate has no actual build selector: ${target}`);
    }
  }
  return selected;
}

export function planRows(selected, architecture, optimize) {
  requireValue(['both', 'amd64', 'arm64'].includes(architecture), 'invalid architecture');
  requireValue(['both', 'Debug', 'ReleaseSafe'].includes(optimize), 'invalid optimization mode');
  const architectures = architecture === 'both' ? ['amd64', 'arm64'] : [architecture];
  const modes = optimize === 'both' ? ['Debug', 'ReleaseSafe'] : [optimize];
  return { include: selected.flatMap(selector => architectures.flatMap(architecture =>
    modes.map(optimize => ({
      selector, architecture, optimize,
      labels: JSON.stringify(['self-hosted', 'Linux', architecture === 'amd64' ? 'X64' : 'ARM64', 'ubuntu2604']),
    })))) };
}

function job(workflow, name) {
  const match = workflow.match(new RegExp(`^  ${name}:\\n([\\s\\S]*?)(?=^  [a-z][a-z-]*:\\n|(?![\\s\\S]))`, 'm'));
  requireValue(match, `missing tooling job: ${name}`);
  return match[1];
}

function step(body, name) {
  const marker = `      - name: ${name}\n`;
  const start = body.indexOf(marker);
  requireValue(start >= 0 && body.indexOf(marker, start + marker.length) < 0,
    `missing or duplicate tooling step: ${name}`);
  const end = body.indexOf('\n      - ', start + marker.length);
  return body.slice(start + marker.length, end < 0 ? undefined : end);
}

export function auditWorkflow(workflow) {
  workflow = workflow.replace(/^[ \t]*#.*$/gm, '');
  const trust = "    if: github.event_name == 'workflow_dispatch' && github.repository == 'cataggar/debz' && startsWith(github.ref, 'refs/heads/')";
  requireValue(/^on:\n  workflow_dispatch:\n/m.test(workflow)
    && !/^\s*(?:push|pull_request|pull_request_target|schedule):/m.test(workflow),
  'tooling must be dispatch-only; never a fork or automatic acceptance route');
  requireValue(/^permissions:\n  contents: read\n  attestations: read\n\n/m.test(workflow),
    'tooling permissions must remain read-only');
  requireValue(!/secrets\.|continue-on-error:|actions\/cache@|\b(?:sudo|chroot|unshare|nsenter|apt-get)\b/.test(workflow),
    'tooling cannot use secrets, build cache restores, failure masking or privileged commands');
  const hosted = job(workflow, 'bind-source');
  const paid = job(workflow, 'tooling');
  for (const body of [hosted, paid]) {
    requireValue(body.split('\n').includes(trust), 'missing trusted branch dispatch guard');
    requireValue(body.includes('          ref: ${{ inputs.source_sha }}\n          persist-credentials: false'),
      'checkout must bind the supplied exact source without persisted credentials');
    requireValue(step(body, 'Install Node 24').includes(
      'uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020')
      && step(body, 'Install Node 24').includes('node-version: 24.20.0'),
    'tooling Node installation must remain pinned');
  }
  requireValue(hosted.includes('    runs-on: ubuntu-24.04'), 'source planning must remain hosted');
  requireValue(paid.includes('    needs: bind-source')
    && paid.includes('    runs-on: ${{ fromJSON(matrix.labels) }}')
    && paid.includes('      matrix: ${{ fromJSON(needs.bind-source.outputs.matrix) }}'),
  'paid rows must use only the validated source plan');
  requireValue(step(hosted, 'Bind candidate and plan pure tooling rows').includes(
    'run: |\n          node --test tools/test-tooling-fleet.mjs\n          node tools/tooling-fleet.mjs plan'),
  'actual source planner and mutation tests must execute before paid scheduling');
  const plan = step(hosted, 'Bind candidate and plan pure tooling rows');
  const run = step(paid, 'Run bound unprivileged tooling selector');
  for (const [body, bindings] of [
    [plan, { SOURCE_SHA: 'inputs.source_sha', SOURCE_TREE: 'inputs.source_tree',
      SELECTORS: 'inputs.selectors', ARCHITECTURE: 'inputs.architecture', OPTIMIZE: 'inputs.optimize' }],
    [run, { SOURCE_SHA: 'inputs.source_sha', SOURCE_TREE: 'inputs.source_tree',
      SELECTOR: 'matrix.selector', ARCHITECTURE: 'matrix.architecture', OPTIMIZE: 'matrix.optimize' }],
  ]) {
    for (const [name, expression] of Object.entries(bindings)) {
      requireValue(body.includes(`          ${name}: \${{ ${expression} }}`),
        `actual tooling consumer lost its ${name} source binding`);
    }
  }
  const compiler = step(paid, 'Install Zig via ghr');
  requireValue(compiler.includes('uses: cataggar/ghr/actions/install@c4be68b52d67d7acd2a7fe6c1e5f126e1754176e')
    && compiler.includes('ghr-version: v0.8.1')
    && compiler.includes('cataggar/zig@v0.16.0\n            RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U'),
  'tooling compiler signature, action and version must remain pinned');
  requireValue(step(paid, 'Validate Zig version').trim() === 'run: test "$(zig version)" = 0.16.0',
    'exact compiler version must be checked before building');
  requireValue(step(paid, 'Run bound unprivileged tooling selector').includes(
    'run: node tools/tooling-fleet.mjs run')
    && paid.indexOf('      - name: Install Zig via ghr') < paid.indexOf('      - name: Validate Zig version')
    && paid.indexOf('      - name: Validate Zig version') < paid.indexOf('      - name: Run bound unprivileged tooling selector'),
  'actual tooling consumer must follow verified compiler installation');
  const actions = [...workflow.matchAll(/uses:\s*([^@\s]+)@([^\s#]+)/g)];
  requireValue(actions.length === 6 && actions.every(match => /^[0-9a-f]{40}$/.test(match[2])),
    'all six tooling action uses must be immutable');
}

export function bindSource(env, root) {
  requireValue(env.GITHUB_EVENT_NAME === 'workflow_dispatch'
    && env.GITHUB_REPOSITORY === 'cataggar/debz'
    && /^refs\/heads\/.+/.test(env.GITHUB_REF ?? ''), 'untrusted tooling dispatch context');
  requireValue(/^[0-9a-f]{40}$/.test(env.SOURCE_SHA ?? '')
    && /^[0-9a-f]{40}$/.test(env.SOURCE_TREE ?? '')
    && env.SOURCE_SHA === env.GITHUB_SHA, 'candidate must equal the exact dispatched commit');
  requireValue(command('git', ['rev-parse', 'HEAD'], { cwd: root }).trim() === env.SOURCE_SHA
    && command('git', ['rev-parse', 'HEAD^{tree}'], { cwd: root }).trim() === env.SOURCE_TREE,
  'candidate checkout commit/tree mismatch');
  requireValue(command('git', ['status', '--porcelain', '--untracked-files=normal'], { cwd: root }).trim() === '',
    'candidate tracked source or untracked source is dirty');
  auditWorkflow(readFileSync(join(root, '.github/workflows/tooling.yml'), 'utf8'));
}

export function inventory(prefix) {
  const bin = join(prefix, 'bin');
  requireValue(existsSync(bin) && !lstatSync(bin).isSymbolicLink(), 'selected producer installed no real bin directory');
  const files = readdirSync(bin).sort().map(name => {
    const path = join(bin, name);
    const stat = lstatSync(path);
    requireValue(stat.isFile() && stat.nlink === 1 && (stat.mode & 0o111) !== 0,
      `installed tool must be a regular executable: ${name}`);
    return { name, mode: stat.mode & 0o777, sha256: createHash('sha256').update(readFileSync(path)).digest('hex') };
  });
  requireValue(files.length > 0, 'selected producer installed no tools');
  return files;
}

function findExecutable(name, path) {
  for (const directory of (path ?? '').split(delimiter)) {
    if (!directory) continue;
    const candidate = join(directory, name);
    if (existsSync(candidate) && (lstatSync(candidate).mode & 0o111) !== 0) return realpathSync(candidate);
  }
  throw new Error(`missing ${name}`);
}

export function runSelector(env, root) {
  bindSource(env, root);
  requireValue(typeof process.getuid === 'function' && process.getuid() !== 0, 'paid tooling refuses root');
  const architecture = { x64: 'amd64', arm64: 'arm64' }[arch()];
  requireValue(architecture === env.ARCHITECTURE, 'native runner architecture mismatch');
  planRows([env.SELECTOR], env.ARCHITECTURE, env.OPTIMIZE);
  requireValue(env.ARCHITECTURE !== 'both' && env.OPTIMIZE !== 'both', 'execution requires one exact matrix coordinate');
  const requested = selectTargets(env.SELECTOR, stepNames(readFileSync(join(root, 'build.zig'), 'utf8')));
  requireValue(requested.length === 1, 'execution requires one exact tooling selector');
  const selected = requested[0];
  requireValue(/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID ?? '')
    && /^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT ?? ''), 'missing exact run identity');
  const zig = findExecutable('zig', env.PATH);
  requireValue(command(zig, ['version'], { env }).trim() === '0.16.0', 'unverified compiler version');
  requireValue(!existsSync(join(root, 'zig-out')), 'normal install prefix is not fresh');
  const workspace = join(root, '.cache/tooling-fleet', env.SOURCE_SHA,
    env.GITHUB_RUN_ID, env.GITHUB_RUN_ATTEMPT, env.ARCHITECTURE, env.OPTIMIZE, selected);
  mkdirSync(dirname(workspace), { recursive: true });
  mkdirSync(workspace); // An existing coordinate/cache is never a fresh execution.
  const reports = join(workspace, 'reports');
  mkdirSync(reports);
  const report = {
    source_sha: env.SOURCE_SHA, source_tree: env.SOURCE_TREE, selector: selected,
    architecture, optimize: env.OPTIMIZE, run_id: env.GITHUB_RUN_ID,
    run_attempt: env.GITHUB_RUN_ATTEMPT, compiler: zig, compiler_version: '0.16.0',
    build_cache: 'fresh-exclusive-no-restore',
    execution: env.GITHUB_ACTIONS === 'true' ? 'github-actions' : 'local-validation',
    acceptance: false, status: 'running',
  };
  writeFileSync(join(reports, 'binding.json'), `${JSON.stringify(report, null, 2)}\n`);
  try {
    const poison = join(workspace, 'no-host-interpreters');
    mkdirSync(poison);
    const forbidden = new Set(['python', 'python2', 'python3', 'pip', 'pip3', 'sudo', 'doas', 'chroot', 'unshare', 'nsenter', 'mount', 'apt', 'apt-get']);
    for (const directory of (env.PATH ?? '').split(delimiter)) {
      if (directory && existsSync(directory)) {
        for (const name of readdirSync(directory)) {
          if (/^(?:python|pip)(?:[0-9.]+)?$/.test(name)) forbidden.add(name);
        }
      }
    }
    for (const name of forbidden) {
      writeFileSync(join(poison, name), '#!/bin/sh\nprintf "forbidden tooling host command: %s\\n" "$0" >&2\nexit 125\n', { mode: 0o755 });
    }
    const childEnv = {
      ...env, PATH: `${poison}${delimiter}${env.PATH}`,
      TMPDIR: join(workspace, 'scratch'),
      ZIG_LOCAL_CACHE_DIR: join(workspace, 'local-cache'),
      ZIG_GLOBAL_CACHE_DIR: join(workspace, 'global-cache'),
    };
    mkdirSync(childEnv.TMPDIR);
    const help = command(zig, ['build', '--help'], { cwd: root, env: childEnv });
    const available = new Set([...help.matchAll(/^  ([a-z][a-z0-9-]+)\s/mg)].map(match => match[1]));
    selectTargets(selected, available);
    const custom = join(workspace, 'custom-prefix');
    const producers = selectors[selected];
    const args = ['-Doptimize=' + env.OPTIMIZE, '-j2', '--summary', 'all'];
    function build(targets, prefix, label) {
      const argv = ['build', ...targets, ...args, '--prefix', prefix];
      appendFileSync(join(reports, 'commands.jsonl'), `${JSON.stringify({ compiler: zig, args: argv })}\n`);
      const result = spawnSync(zig, argv, { cwd: root, env: childEnv, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
      writeFileSync(join(reports, `${label}.log`), `${result.stdout ?? ''}${result.stderr ?? ''}${result.error?.message ?? ''}`);
      requireValue(!result.error && result.status === 0, `focused ${label} failed: ${result.status}; see retained log`);
    }
    build(producers, join(root, 'zig-out'), 'normal-install');
    report.normal_install = inventory(join(root, 'zig-out'));
    build(producers, custom, 'custom-install');
    report.custom_install = inventory(custom);
    assert.deepEqual(report.custom_install, report.normal_install, 'actual normal/custom installed inventories differ');
    build([selected], custom, 'focused-tests');
    bindSource(env, root);
    report.status = 'success';
  } catch (error) {
    report.status = 'failure';
    report.error = error.message;
    throw error;
  } finally {
    writeFileSync(join(reports, 'binding.json'), `${JSON.stringify(report, null, 2)}\n`);
  }
}

export function main(action, env = process.env, root = process.cwd()) {
  if (action === 'check-workflow') {
    auditWorkflow(readFileSync(join(root, '.github/workflows/tooling.yml'), 'utf8'));
  } else if (action === 'plan') {
    bindSource(env, root);
    const selected = selectTargets(env.SELECTORS, stepNames(readFileSync(join(root, 'build.zig'), 'utf8')));
    const matrix = JSON.stringify(planRows(selected, env.ARCHITECTURE, env.OPTIMIZE));
    requireValue(env.GITHUB_OUTPUT, 'missing Actions output path');
    appendFileSync(env.GITHUB_OUTPUT, `matrix=${matrix}\n`);
    console.log(matrix);
  } else if (action === 'run') {
    runSelector(env, root);
  } else {
    throw new Error('usage: tooling-fleet.mjs plan|run|check-workflow');
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv[2]); } catch (error) {
    console.error(`tooling fleet refused: ${error.message}`);
    process.exitCode = 1;
  }
}
