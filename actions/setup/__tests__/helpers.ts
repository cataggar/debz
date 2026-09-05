import { gzipSync } from 'node:zlib';

export interface TestTarEntry {
  name: string;
  type: '0' | '1' | '2' | '3' | '4' | '5' | '6';
  data?: Buffer;
  mode?: number;
}

function writeString(header: Buffer, offset: number, length: number, value: string): void {
  const bytes = Buffer.from(value, 'ascii');
  if (bytes.length > length) {
    throw new Error(`test tar field is too long: ${value}`);
  }
  bytes.copy(header, offset);
}

function writeOctal(header: Buffer, offset: number, length: number, value: number): void {
  const text = value.toString(8).padStart(length - 1, '0');
  writeString(header, offset, length, `${text}\0`);
}

function headerFor(entry: TestTarEntry): Buffer {
  const header = Buffer.alloc(512);
  const directory = entry.type === '5';
  const data = directory ? Buffer.alloc(0) : (entry.data ?? Buffer.alloc(0));
  writeString(header, 0, 100, entry.name + (directory && !entry.name.endsWith('/') ? '/' : ''));
  writeOctal(header, 100, 8, entry.mode ?? (directory ? 0o755 : 0o644));
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, data.length);
  writeOctal(header, 136, 12, 1_700_000_000);
  header.fill(0x20, 148, 156);
  writeString(header, 156, 1, entry.type);
  writeString(header, 257, 6, 'ustar ');
  header[263] = 0x20;
  header[264] = 0;
  writeString(header, 265, 32, 'root');
  writeString(header, 297, 32, 'root');
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  writeString(header, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `);
  return header;
}

export function makeTar(entries: TestTarEntry[]): Buffer {
  const chunks: Buffer[] = [];
  for (const entry of entries) {
    const data = entry.type === '5' ? Buffer.alloc(0) : (entry.data ?? Buffer.alloc(0));
    chunks.push(headerFor(entry), data);
    const padding = (512 - (data.length % 512)) % 512;
    if (padding > 0) {
      chunks.push(Buffer.alloc(padding));
    }
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

export function makeArchive(
  root = 'debz-1.2.3-linux-x64',
  overrides: TestTarEntry[] = [],
): Buffer {
  const entries: TestTarEntry[] = [
    { name: root, type: '5' },
    { name: `${root}/bin`, type: '5' },
    {
      name: `${root}/bin/debz`,
      type: '0',
      mode: 0o755,
      data: Buffer.from('test debz executable\n'),
    },
    { name: `${root}/share`, type: '5' },
    {
      name: `${root}/share/README.md`,
      type: '0',
      data: Buffer.from('fixture\n'),
    },
    ...overrides,
  ];
  return gzipSync(makeTar(entries), { level: 9 });
}

export function releaseMetadata(
  digest: string,
  size: number,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    tag_name: 'v1.2.3',
    draft: false,
    prerelease: false,
    assets: [
      {
        id: 123,
        name: 'debz-1.2.3-linux-x64.tar.gz',
        state: 'uploaded',
        size,
        digest: `sha256:${digest}`,
        url: 'https://api.github.com/repos/cataggar/debz/releases/assets/123',
      },
    ],
    ...overrides,
  };
}
