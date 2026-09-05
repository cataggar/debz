import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';

import { SetupError } from './errors.js';

export const SHA256_PATTERN = /^[0-9a-f]{64}$/;

export function normalizeTrustedSha256(value: string): string | undefined {
  if (value.length === 0) {
    return undefined;
  }
  if (value !== value.trim() || !/^[0-9A-Fa-f]{64}$/.test(value)) {
    throw new SetupError('sha256 must be exactly 64 hexadecimal characters');
  }
  return value.toLowerCase();
}

export function sha256Bytes(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

export async function sha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  await new Promise<void>((resolve, reject) => {
    const stream = createReadStream(path);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', resolve);
  });
  return hash.digest('hex');
}
