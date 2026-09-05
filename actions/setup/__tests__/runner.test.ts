import assert from 'node:assert/strict';
import { chmod, mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { verifyExecutableVersion } from '../src/runner.js';

const testRoot = path.resolve(process.cwd(), '../../.tmp/setup-action-tests/runner');

test.before(async () => {
  await rm(testRoot, { recursive: true, force: true });
  await mkdir(testRoot, { recursive: true });
});

test.after(async () => {
  await rm(testRoot, { recursive: true, force: true });
});

async function script(name: string, body: string): Promise<string> {
  const filename = path.join(testRoot, name);
  await writeFile(filename, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  await chmod(filename, 0o755);
  return filename;
}

test('version command must return the exact requested version and clean stderr', async () => {
  const executable = await script(
    'current',
    '[ "$1" = version ] || exit 2\nprintf "1.2.3\\n"',
  );
  await verifyExecutableVersion(executable, '1.2.3');

  const mismatch = await script('mismatch', 'printf "1.2.4\\n"');
  await assert.rejects(verifyExecutableVersion(mismatch, '1.2.3'), /instead of/);

  const noisy = await script('noisy', 'printf "1.2.3\\n"\nprintf "noise\\n" >&2');
  await assert.rejects(verifyExecutableVersion(noisy, '1.2.3'), /unexpected stderr/);
});

test('published pre-v0.3 releases use the documented compatibility check only', async () => {
  const executable = await script(
    'legacy',
    "if [ \"$1\" = version ]; then printf \"debz: unknown command 'version'\\n\" >&2; exit 2; fi\n" +
      '[ "$1" = --version ] || exit 2\n' +
      'printf "0.2.0\\n"',
  );
  await verifyExecutableVersion(executable, '0.2.0');

  await assert.rejects(
    verifyExecutableVersion(executable, '0.3.0'),
    /version check failed/,
  );
});
