import assert from 'node:assert/strict';
import test from 'node:test';

import { ActionsCacheV2 } from '../src/cache.js';
import type { BufferedResponse, RequestSpec } from '../src/http.js';

function response(statusCode: number, body: string | Buffer): BufferedResponse {
  return {
    statusCode,
    headers: {},
    body: Buffer.isBuffer(body) ? body : Buffer.from(body),
  };
}

function environment(): NodeJS.ProcessEnv {
  return {
    ACTIONS_CACHE_SERVICE_V2: 'true',
    ACTIONS_RESULTS_URL: 'https://results-receiver.actions.githubusercontent.com/',
    ACTIONS_RUNTIME_TOKEN: 'runtime-token',
  };
}

test('raw cache restore uses an exact key and never extracts a service archive', async () => {
  const requests: RequestSpec[] = [];
  const archive = Buffer.from('opaque authenticated release archive');
  const cache = new ActionsCacheV2(environment(), async (request) => {
    requests.push(request);
    if (requests.length === 1) {
      return response(
        200,
        JSON.stringify({
          ok: true,
          matched_key: 'exact-key',
          signed_download_url:
            'https://debzcache.blob.core.windows.net/results/archive?sig=redacted',
        }),
      );
    }
    return response(200, archive);
  });
  assert.deepEqual(await cache.restoreCache('exact-key', archive.length), archive);
  assert.equal(requests.length, 2);
  assert.equal(requests[0]?.method, 'POST');
  assert.equal(requests[0]?.headers.Authorization, 'Bearer runtime-token');
  const lookup = JSON.parse((requests[0]?.body as Buffer).toString()) as Record<
    string,
    unknown
  >;
  assert.equal(lookup.key, 'exact-key');
  assert.deepEqual(lookup.restore_keys, []);
  assert.match(String(lookup.version), /^[0-9a-f]{64}$/);
  assert.equal(requests[1]?.method, 'GET');
  assert.equal(requests[1]?.headers.Authorization, undefined);
  assert.equal(requests[1]?.url.hostname, 'debzcache.blob.core.windows.net');
});

test('cache restore rejects prefix matches and unapproved blob hosts', async () => {
  const prefix = new ActionsCacheV2(environment(), async () =>
    response(
      200,
      JSON.stringify({
        ok: true,
        matched_key: 'prefix-key',
        signed_download_url:
          'https://debzcache.blob.core.windows.net/results/archive?sig=redacted',
      }),
    ),
  );
  await assert.rejects(prefix.restoreCache('exact-key', 10), /unexpected key/);

  const host = new ActionsCacheV2(environment(), async () =>
    response(
      200,
      JSON.stringify({
        ok: true,
        matched_key: 'exact-key',
        signed_download_url: 'https://evil.invalid/archive',
      }),
    ),
  );
  await assert.rejects(host.restoreCache('exact-key', 10), /unapproved signed blob URL/);
});

test('cache misses and unavailable cache service return no bytes', async () => {
  const unavailable = new ActionsCacheV2({}, async () => {
    throw new Error('request should not run');
  });
  assert.equal(unavailable.isFeatureAvailable(), false);
  assert.equal(await unavailable.restoreCache('key', 10), undefined);

  const miss = new ActionsCacheV2(environment(), async () =>
    response(200, JSON.stringify({ ok: false })),
  );
  assert.equal(await miss.restoreCache('key', 10), undefined);
});

test('cache save uploads only the verified raw release archive without authorization', async () => {
  const requests: RequestSpec[] = [];
  const archive = Buffer.from('verified release archive');
  const cache = new ActionsCacheV2(environment(), async (request) => {
    requests.push(request);
    if (request.url.pathname.endsWith('/CreateCacheEntry')) {
      return response(
        200,
        JSON.stringify({
          ok: true,
          signed_upload_url:
            'https://debzcache.blob.core.windows.net/results/archive?sig=redacted',
        }),
      );
    }
    if (request.method === 'PUT') {
      return response(201, '');
    }
    return response(200, JSON.stringify({ ok: true, entry_id: '42' }));
  });
  assert.equal(await cache.saveCache('exact-key', archive), 42);
  assert.equal(requests.length, 3);
  assert.equal(requests[1]?.method, 'PUT');
  assert.deepEqual(requests[1]?.body, archive);
  assert.equal(requests[1]?.headers.Authorization, undefined);
  assert.equal(requests[1]?.headers['x-ms-blob-type'], 'BlockBlob');
  assert.equal(requests[2]?.headers.Authorization, 'Bearer runtime-token');
});

test('cache modes honor runner read/write restrictions', async () => {
  let calls = 0;
  const readDisabled = new ActionsCacheV2(
    { ...environment(), ACTIONS_CACHE_MODE: 'write-only' },
    async () => {
      calls += 1;
      return response(500, '');
    },
  );
  assert.equal(await readDisabled.restoreCache('key', 10), undefined);

  const writeDisabled = new ActionsCacheV2(
    { ...environment(), ACTIONS_CACHE_MODE: 'read' },
    async () => {
      calls += 1;
      return response(500, '');
    },
  );
  assert.equal(await writeDisabled.saveCache('key', Buffer.from('archive')), -1);
  assert.equal(calls, 0);
});
