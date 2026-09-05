import assert from 'node:assert/strict';
import { lstat, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  ActionsCacheV2,
  createTransferArea,
  type BlobAdapter,
  type Requester,
} from '../src/cache.js';

const testRoot = path.resolve(process.cwd(), '../../.tmp/download-action-tests/cache');
const environment = {
  ACTIONS_CACHE_SERVICE_V2: 'true',
  ACTIONS_RESULTS_URL: 'https://results.actions.githubusercontent.com/',
  ACTIONS_RUNTIME_TOKEN: 'runtime-token',
};

test.beforeEach(async () => {
  await rm(testRoot, { recursive: true, force: true });
  await mkdir(testRoot, { recursive: true });
});

test.after(async () => {
  await rm(testRoot, { recursive: true, force: true });
});

test('restores one opaque blob without path-dependent cache versioning', async () => {
  const victim = path.join(testRoot, 'debz');
  await writeFile(victim, 'trusted executable');
  const hostileArchive = Buffer.from(
    '/absolute/tool/debz\n../../workspace/credential\nsymlink\nfifo\n',
  );
  const payloads: Record<string, unknown>[] = [];
  const requester: Requester = async (request) => {
    payloads.push(JSON.parse(request.body.toString('utf8')) as Record<string, unknown>);
    assert.equal(request.headers.Authorization, 'Bearer runtime-token');
    return {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      body: Buffer.from(
        JSON.stringify({
          ok: true,
          matched_key: 'primary',
          signed_download_url:
            'https://cache.blob.core.windows.net/container/blob?sig=masked',
        }),
      ),
    };
  };
  const destinations: string[] = [];
  const blobs: BlobAdapter = {
    async download(_url, destination, maximumBytes) {
      assert.equal(maximumBytes, 4096);
      destinations.push(destination);
      await writeFile(destination, hostileArchive);
      return hostileArchive.length;
    },
    async upload() {
      assert.fail('restore must not upload');
    },
  };
  const client = new ActionsCacheV2(environment, requester, blobs);
  const first = path.join(testRoot, 'one.cache');
  const second = path.join(testRoot, 'relocated.cache');
  assert.equal(await client.restore(first, 'primary', 'prefix-', 4096), 'primary');
  assert.equal(await client.restore(second, 'primary', 'prefix-', 4096), 'primary');
  assert.deepEqual(destinations, [first, second]);
  assert.equal(await readFile(victim, 'utf8'), 'trusted executable');
  assert.deepEqual(await readFile(first), hostileArchive);
  assert.deepEqual(await readFile(second), hostileArchive);
  assert.equal(payloads[0].version, payloads[1].version);
  assert.ok(!JSON.stringify(payloads).includes(testRoot));
  assert.deepEqual(payloads[0].restore_keys, ['prefix-']);
});

test('fails closed on an unapproved matched blob endpoint', async () => {
  const destination = path.join(testRoot, 'restored.cache');
  const client = new ActionsCacheV2(
    environment,
    async () => ({
      statusCode: 200,
      headers: {},
      body: Buffer.from(
        JSON.stringify({
          ok: true,
          matched_key: 'primary',
          signed_download_url: 'https://attacker.invalid/archive',
        }),
      ),
    }),
    {
      async download() {
        assert.fail('unapproved blob URL must not be downloaded');
      },
      async upload() {
        assert.fail('restore must not upload');
      },
    },
  );
  await assert.rejects(
    client.restore(destination, 'primary', 'prefix-', 4096),
    /could not be safely staged/,
  );
  await assert.rejects(lstat(destination));
});

test('an unavailable lookup is a miss before any cache blob is selected', async () => {
  const client = new ActionsCacheV2(
    environment,
    async () => {
      throw new Error('service unavailable');
    },
    {
      async download() {
        assert.fail('lookup failure must not download');
      },
      async upload() {
        assert.fail('restore must not upload');
      },
    },
  );
  assert.equal(
    await client.restore(path.join(testRoot, 'miss.cache'), 'primary', 'prefix-', 4096),
    undefined,
  );
});

test('a matched oversized or truncated blob is never downgraded to a miss', async () => {
  const destination = path.join(testRoot, 'bad.cache');
  const client = new ActionsCacheV2(
    environment,
    async () => ({
      statusCode: 200,
      headers: {},
      body: Buffer.from(
        JSON.stringify({
          ok: true,
          matched_key: 'primary',
          signed_download_url:
            'https://cache.blob.core.windows.net/container/blob?sig=masked',
        }),
      ),
    }),
    {
      async download() {
        await writeFile(destination, 'partial');
        throw new Error('truncated');
      },
      async upload() {
        assert.fail('restore must not upload');
      },
    },
  );
  await assert.rejects(
    client.restore(destination, 'primary', 'prefix-', 4),
    /could not be safely staged/,
  );
  await assert.rejects(lstat(destination));
});

test('uploads only the caller-provided opaque archive and finalizes its size', async () => {
  const source = path.join(testRoot, 'export.cache');
  await writeFile(source, 'verified archive');
  const payloads: Record<string, unknown>[] = [];
  const requester: Requester = async (request) => {
    const payload = JSON.parse(request.body.toString('utf8')) as Record<string, unknown>;
    payloads.push(payload);
    if (request.url.pathname.endsWith('/CreateCacheEntry')) {
      return {
        statusCode: 200,
        headers: {},
        body: Buffer.from(
          JSON.stringify({
            ok: true,
            signed_upload_url:
              'https://cache.blob.core.windows.net/container/blob?sig=masked',
          }),
        ),
      };
    }
    return {
      statusCode: 200,
      headers: {},
      body: Buffer.from(JSON.stringify({ ok: true, entry_id: '1' })),
    };
  };
  let uploaded = false;
  const client = new ActionsCacheV2(environment, requester, {
    async download() {
      assert.fail('save must not download');
    },
    async upload(_url, filename, size) {
      uploaded = true;
      assert.equal(filename, source);
      assert.equal(size, Buffer.byteLength('verified archive'));
      assert.equal(await readFile(filename, 'utf8'), 'verified archive');
    },
  });
  await client.save(source, 'primary', 4096);
  assert.equal(uploaded, true);
  assert.equal(payloads.length, 2);
  assert.equal(payloads[0].version, payloads[1].version);
  assert.equal(payloads[1].size_bytes, String(Buffer.byteLength('verified archive')));
  assert.ok(!JSON.stringify(payloads).includes(source));
});

test('refuses to publish a missing or non-regular export archive', async () => {
  const client = new ActionsCacheV2(environment, async () => {
    assert.fail('invalid local archive must fail before cache service access');
  }, {
    async download() {
      assert.fail('save must not download');
    },
    async upload() {
      assert.fail('invalid local archive must not upload');
    },
  });
  await assert.rejects(
    client.save(path.join(testRoot, 'missing.cache'), 'primary', 4096),
  );
  const directory = path.join(testRoot, 'directory.cache');
  await mkdir(directory);
  await assert.rejects(client.save(directory, 'primary', 4096), /regular file/);
});

test('treats an immutable cache reservation race as benign', async () => {
  const source = path.join(testRoot, 'export.cache');
  await writeFile(source, 'verified archive');
  const client = new ActionsCacheV2(
    environment,
    async () => ({
      statusCode: 200,
      headers: {},
      body: Buffer.from(JSON.stringify({ ok: false })),
    }),
    {
      async download() {
        assert.fail('save must not download');
      },
      async upload() {
        assert.fail('a lost reservation race must not upload');
      },
    },
  );
  await client.save(source, 'primary', 4096);
});

test('transfer directories are private, isolated, and removable', async () => {
  const first = await createTransferArea(testRoot);
  const second = await createTransferArea(testRoot);
  assert.notEqual(first.root, second.root);
  assert.equal((await lstat(first.root)).mode & 0o777, 0o700);
  assert.equal(path.dirname(first.restoredArchive), first.root);
  assert.equal(path.dirname(first.exportArchive), first.root);
  await first.cleanup();
  await second.cleanup();
  await assert.rejects(lstat(first.root));
  await assert.rejects(lstat(second.root));
});
