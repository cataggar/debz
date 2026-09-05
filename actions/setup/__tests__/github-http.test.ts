import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DebzGitHubClient,
  RELEASE_REPOSITORY_ID,
  selectReleaseAsset,
} from '../src/github.js';
import {
  GitHubHttpClient,
  type BufferedResponse,
  type RequestSpec,
} from '../src/http.js';
import { releaseMetadata } from './helpers.js';

const digest = 'a'.repeat(64);

function response(
  statusCode: number,
  body: string | Buffer,
  headers: Record<string, string> = {},
): BufferedResponse {
  return {
    statusCode,
    headers,
    body: Buffer.isBuffer(body) ? body : Buffer.from(body),
  };
}

test('release selection requires one exact uploaded gzip asset and digest', () => {
  const selected = selectReleaseAsset(
    releaseMetadata(digest, 123),
    'v1.2.3',
    '1.2.3',
    'linux-x64',
  );
  assert.equal(selected.name, 'debz-1.2.3-linux-x64.tar.gz');
  assert.equal(selected.digest, digest);
  assert.equal(selected.apiURL.href, 'https://api.github.com/repos/cataggar/debz/releases/assets/123');
});

test('release selection fails closed on malformed metadata', () => {
  const valid = releaseMetadata(digest, 123);
  const validAsset = (valid.assets as Record<string, unknown>[])[0];
  const cases: Array<[unknown, RegExp]> = [
    [{ ...valid, tag_name: 'v9.9.9' }, /instead of requested/],
    [{ ...valid, draft: true }, /draft/],
    [{ ...valid, assets: [] }, /exactly one/],
    [{ ...valid, assets: [validAsset, { ...validAsset }] }, /found 2/],
    [{ ...valid, assets: [{ ...validAsset, digest: null }] }, /not a string/],
    [
      { ...valid, assets: [{ ...validAsset, digest: `sha256:${'A'.repeat(64)}` }] },
      /lowercase/,
    ],
    [{ ...valid, assets: [{ ...validAsset, digest: `sha512:${digest}` }] }, /lowercase/],
    [{ ...valid, assets: [{ ...validAsset, size: 0 }] }, /size must be/],
    [
      {
        ...valid,
        assets: [{ ...validAsset, url: 'https://example.invalid/asset' }],
      },
      /expected GitHub repository/,
    ],
  ];
  for (const [metadata, expectedError] of cases) {
    assert.throws(
      () => selectReleaseAsset(metadata, 'v1.2.3', '1.2.3', 'linux-x64'),
      expectedError,
    );
  }
});

test('asset redirects strip authorization before release storage', async () => {
  const requests: RequestSpec[] = [];
  const requester = async (spec: RequestSpec): Promise<BufferedResponse> => {
    requests.push(spec);
    if (requests.length === 1) {
      return response(302, '', {
        location:
          'https://release-assets.githubusercontent.com/github-production-release-asset/1/asset?sig=secret',
      });
    }
    return response(200, 'asset', {
      'content-length': '5',
      'content-encoding': 'identity',
    });
  };
  const client = new GitHubHttpClient('token-value', requester, async () => {});
  const bytes = await client.downloadAsset(
    new URL('https://api.github.com/repos/cataggar/debz/releases/assets/123'),
    5,
  );
  assert.equal(bytes.toString(), 'asset');
  assert.equal(requests[0]?.headers.Authorization, 'Bearer token-value');
  assert.equal(requests[1]?.headers.Authorization, undefined);
});

test('asset redirects to an unapproved host fail without forwarding a token', async () => {
  const requests: RequestSpec[] = [];
  const client = new GitHubHttpClient(
    'token-value',
    async (spec) => {
      requests.push(spec);
      return response(302, '', { location: 'https://evil.invalid/steal' });
    },
    async () => {},
  );
  const message = await client
    .downloadAsset(
      new URL('https://api.github.com/repos/cataggar/debz/releases/assets/123'),
      5,
    )
    .then(
      () => 'unexpected success',
      (error: Error) => error.message,
    );
  assert.match(message, /unexpected release asset redirect/);
  assert.equal(requests.length, 1);
  assert.doesNotMatch(message, /token-value/);
});

test('only transient HTTP responses are retried', async () => {
  let calls = 0;
  const sleeps: number[] = [];
  const transient = new GitHubHttpClient(
    undefined,
    async () => {
      calls += 1;
      return calls === 1
        ? response(503, JSON.stringify({ message: 'try again' }))
        : response(200, JSON.stringify({ ok: true }), { 'content-type': 'application/json' });
    },
    async (delay) => {
      sleeps.push(delay);
    },
  );
  assert.deepEqual(
    (await transient.getJSON<{ ok: boolean }>(new URL('https://api.github.com/test'))).value,
    { ok: true },
  );
  assert.equal(calls, 2);
  assert.equal(sleeps.length, 1);

  calls = 0;
  const permanent = new GitHubHttpClient(
    undefined,
    async () => {
      calls += 1;
      return response(404, JSON.stringify({ message: 'missing' }), {
        'content-type': 'application/json',
      });
    },
    async () => {},
  );
  await assert.rejects(
    permanent.getJSON(new URL('https://api.github.com/missing')),
    /HTTP 404.*missing/,
  );
  assert.equal(calls, 1);
});

test('asset response bounds and exact size are enforced', async () => {
  const client = new GitHubHttpClient(
    undefined,
    async () => response(200, 'too long', { 'content-length': '8' }),
    async () => {},
  );
  await assert.rejects(
    client.downloadAsset(
      new URL('https://api.github.com/repos/cataggar/debz/releases/assets/123'),
      5,
    ),
    /size mismatch/,
  );
});

test('release lookup uses only the requested exact tag and annotated tags are peeled', async () => {
  const urls: string[] = [];
  const fakeHTTP = {
    getJSON: async (url: URL): Promise<{ value: unknown; headers: Record<string, string> }> => {
      urls.push(url.href);
      if (url.pathname.includes('/releases/tags/')) {
        return { value: { tag_name: 'v1.2.3' }, headers: {} };
      }
      if (url.pathname.includes('/git/ref/tags/')) {
        return {
          value: { object: { type: 'tag', sha: 'a'.repeat(40) } },
          headers: {},
        };
      }
      return {
        value: {
          tag: 'v1.2.3',
          object: { type: 'commit', sha: 'b'.repeat(40) },
        },
        headers: {},
      };
    },
  };
  const client = new DebzGitHubClient(fakeHTTP as unknown as GitHubHttpClient);
  await client.getRelease('v1.2.3');
  assert.equal(await client.resolveTagCommit('v1.2.3'), 'b'.repeat(40));
  assert.equal(
    urls[0],
    'https://api.github.com/repos/cataggar/debz/releases/tags/v1.2.3',
  );
  assert.ok(urls.every((url) => !url.includes('/latest')));
});

test('attestation responses are repository-bound and bounded to one page', async () => {
  const fakeHTTP = {
    getJSON: async (): Promise<{ value: unknown; headers: Record<string, string> }> => ({
      value: {
        attestations: [{ repository_id: RELEASE_REPOSITORY_ID, bundle: { valid: true } }],
      },
      headers: {},
    }),
  };
  const client = new DebzGitHubClient(fakeHTTP as unknown as GitHubHttpClient);
  assert.deepEqual(await client.getAttestationBundles(digest), [{ valid: true }]);

  fakeHTTP.getJSON = async () => ({
    value: { attestations: [{ repository_id: 1, bundle: {} }] },
    headers: {},
  });
  await assert.rejects(client.getAttestationBundles(digest), /unexpected repository/);

  fakeHTTP.getJSON = async () => ({
    value: { attestations: [{ repository_id: RELEASE_REPOSITORY_ID, bundle: {} }] },
    headers: { link: '<https://api.github.com/next>; rel="next"' },
  });
  await assert.rejects(client.getAttestationBundles(digest), /100-bundle limit/);
});
