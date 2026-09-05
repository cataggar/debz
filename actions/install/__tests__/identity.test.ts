import assert from 'node:assert/strict';
import { appendFile, mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  captureOptionalFileIdentity,
  verifyOptionalFileIdentity,
} from '../src/identity.js';
import { testRoot } from './helpers.js';

test('detects an in-place transaction-result change', async () => {
  const directory = path.join(testRoot, 'identity');
  const result = path.join(directory, 'transaction-result.json');
  await mkdir(directory, { recursive: true });
  await writeFile(result, '{}\n');
  const identity = await captureOptionalFileIdentity(result);
  await appendFile(result, ' ');
  await assert.rejects(
    verifyOptionalFileIdentity(identity),
    /changed during final verification/u,
  );
  await rm(directory, { recursive: true, force: true });
});
