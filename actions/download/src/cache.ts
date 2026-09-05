import { createHash } from 'node:crypto';
import { chmod, lstat, mkdtemp, realpath, rm, stat } from 'node:fs/promises';
import type { IncomingHttpHeaders } from 'node:http';
import * as https from 'node:https';
import path from 'node:path';

import * as core from '@actions/core';
import { BlockBlobClient } from '@azure/storage-blob';

import { DownloadActionError } from './errors.js';

const CACHE_VERSION = createHash('sha256')
  .update('debz-package-cache-opaque-archive-v1')
  .digest('hex');
const CACHE_API_MAX_BYTES = 64 * 1024;
const CACHE_CONTROL_TIMEOUT_MS = 30_000;
const CACHE_TRANSFER_TIMEOUT_MS = 30 * 60_000;
const RESULTS_HOST_SUFFIX = '.actions.githubusercontent.com';
const BLOB_HOST_SUFFIX = '.blob.core.windows.net';

export interface CacheAdapter {
  isFeatureAvailable(): boolean;
  restore(
    destination: string,
    primaryKey: string,
    restorePrefix: string,
    maximumBytes: number,
  ): Promise<string | undefined>;
  save(source: string, primaryKey: string, maximumBytes: number): Promise<void>;
}

export interface TransferArea {
  root: string;
  restoredArchive: string;
  exportArchive: string;
  cleanup(): Promise<void>;
}

interface RequestSpec {
  url: URL;
  method: 'POST';
  headers: Record<string, string>;
  body: Buffer;
  maxBytes: number;
  timeoutMs: number;
}

interface BufferedResponse {
  statusCode: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

export type Requester = (request: RequestSpec) => Promise<BufferedResponse>;

export interface BlobAdapter {
  download(url: URL, destination: string, maximumBytes: number): Promise<number>;
  upload(url: URL, source: string, size: number): Promise<void>;
}

export const nodeRequester: Requester = async (spec) =>
  await new Promise<BufferedResponse>((resolve, reject) => {
    const agent = new https.Agent({ keepAlive: false, maxSockets: 4 });
    const request = https.request(
      spec.url,
      {
        method: spec.method,
        headers: spec.headers,
        agent,
      },
      (response) => {
        const chunks: Buffer[] = [];
        let length = 0;
        const rawLength = response.headers['content-length'];
        const lengthText = Array.isArray(rawLength) ? rawLength[0] : rawLength;
        const declaredLength =
          lengthText === undefined || !/^(0|[1-9]\d*)$/.test(lengthText)
            ? undefined
            : Number(lengthText);
        if (
          lengthText !== undefined &&
          (declaredLength === undefined ||
            !Number.isSafeInteger(declaredLength) ||
            declaredLength > spec.maxBytes)
        ) {
          response.destroy();
          reject(new DownloadActionError('Actions cache response has an invalid size'));
          return;
        }
        response.on('data', (chunk: Buffer | string) => {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          length += bytes.length;
          if (length > spec.maxBytes) {
            response.destroy(
              new DownloadActionError(
                `Actions cache response exceeded ${spec.maxBytes} bytes`,
              ),
            );
            return;
          }
          chunks.push(bytes);
        });
        response.on('error', reject);
        response.on('end', () => {
          if (declaredLength !== undefined && declaredLength !== length) {
            reject(new DownloadActionError('Actions cache response was truncated'));
            return;
          }
          resolve({
            statusCode: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks, length),
          });
        });
      },
    );
    const timer = setTimeout(() => {
      request.destroy(new DownloadActionError('Actions cache request timed out'));
    }, spec.timeoutMs);
    timer.unref();
    request.on('close', () => clearTimeout(timer));
    request.on('error', reject);
    request.write(spec.body);
    request.end();
  });

export class AzureBlobAdapter implements BlobAdapter {
  async download(
    url: URL,
    destination: string,
    maximumBytes: number,
  ): Promise<number> {
    core.setSecret(url.href);
    const client = new BlockBlobClient(url.href);
    const properties = await client.getProperties({
      abortSignal: AbortSignal.timeout(CACHE_TRANSFER_TIMEOUT_MS),
    });
    const size = properties.contentLength;
    if (
      size === undefined ||
      !Number.isSafeInteger(size) ||
      size <= 0 ||
      size > maximumBytes
    ) {
      throw new DownloadActionError('cache blob has an invalid or excessive size');
    }
    await client.downloadToFile(destination, 0, size, {
      abortSignal: AbortSignal.timeout(CACHE_TRANSFER_TIMEOUT_MS),
      maxRetryRequests: 3,
    });
    await chmod(destination, 0o600);
    await validateArchiveFile(destination, maximumBytes, size);
    return size;
  }

  async upload(url: URL, source: string, size: number): Promise<void> {
    if (size <= 0) throw new DownloadActionError('cache upload size is invalid');
    core.setSecret(url.href);
    const client = new BlockBlobClient(url.href);
    await client.uploadFile(source, {
      abortSignal: AbortSignal.timeout(CACHE_TRANSFER_TIMEOUT_MS),
      blockSize: 8 * 1024 * 1024,
      concurrency: 4,
      conditions: {},
      onProgress: () => {},
    });
  }
}

export class ActionsCacheV2 implements CacheAdapter {
  constructor(
    private readonly environment: NodeJS.ProcessEnv = process.env,
    private readonly requester: Requester = nodeRequester,
    private readonly blobs: BlobAdapter = new AzureBlobAdapter(),
  ) {}

  isFeatureAvailable(): boolean {
    return Boolean(
      cacheMode(this.environment) !== 'none' &&
      this.environment.ACTIONS_CACHE_SERVICE_V2 &&
        this.environment.ACTIONS_RESULTS_URL &&
        this.environment.ACTIONS_RUNTIME_TOKEN,
    );
  }

  async restore(
    destination: string,
    primaryKey: string,
    restorePrefix: string,
    maximumBytes: number,
  ): Promise<string | undefined> {
    if (!this.isFeatureAvailable() || !cacheReadable(this.environment)) {
      return undefined;
    }
    let response: Record<string, unknown>;
    try {
      response = await this.rpc('GetCacheEntryDownloadURL', {
        key: primaryKey,
        restore_keys: [restorePrefix],
        version: CACHE_VERSION,
      });
    } catch {
      core.warning(
        'GitHub Actions cache lookup failed; debz will continue without restored candidates',
      );
      return undefined;
    }
    if (response.ok !== true) return undefined;
    const matchedKey = responseString(response, 'matched_key', 'matchedKey');
    const signedURL = responseString(
      response,
      'signed_download_url',
      'signedDownloadUrl',
    );
    if (!matchedKey || !signedURL) {
      throw new DownloadActionError('cache restore response omitted required fields');
    }
    if (matchedKey !== primaryKey && !matchedKey.startsWith(restorePrefix)) {
      throw new DownloadActionError(
        'cache restore response returned a key outside the requested prefix',
      );
    }
    try {
      await rm(destination, { force: true });
      await this.blobs.download(
        validateBlobURL(signedURL),
        destination,
        maximumBytes,
      );
      await validateArchiveFile(destination, maximumBytes);
    } catch {
      await rm(destination, { force: true }).catch(() => {});
      throw new DownloadActionError('matched cache blob could not be safely staged');
    }
    return matchedKey;
  }

  async save(
    source: string,
    primaryKey: string,
    maximumBytes: number,
  ): Promise<void> {
    const size = await validateArchiveFile(source, maximumBytes);
    if (!this.isFeatureAvailable() || !cacheWritable(this.environment)) return;
    try {
      const create = await this.rpc('CreateCacheEntry', {
        key: primaryKey,
        version: CACHE_VERSION,
      });
      if (create.ok !== true) {
        core.info('The immutable package cache key is already reserved');
        return;
      }
      const signedURL = responseString(
        create,
        'signed_upload_url',
        'signedUploadUrl',
      );
      if (!signedURL) {
        throw new DownloadActionError('cache reservation omitted its upload URL');
      }
      await this.blobs.upload(validateBlobURL(signedURL), source, size);
      const finalize = await this.rpc('FinalizeCacheEntryUpload', {
        key: primaryKey,
        version: CACHE_VERSION,
        size_bytes: String(size),
      });
      if (finalize.ok !== true) {
        throw new DownloadActionError('cache upload could not be finalized');
      }
    } catch {
      core.warning(
        'GitHub Actions cache save was unavailable or the immutable key already exists',
      );
    }
  }

  private async rpc(
    method:
      | 'CreateCacheEntry'
      | 'FinalizeCacheEntryUpload'
      | 'GetCacheEntryDownloadURL',
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const baseURL = validateServiceURL(this.environment.ACTIONS_RESULTS_URL ?? '');
    const token = this.environment.ACTIONS_RUNTIME_TOKEN;
    if (!token) {
      throw new DownloadActionError('Actions cache runtime token is unavailable');
    }
    core.setSecret(token);
    const body = Buffer.from(JSON.stringify(payload));
    const url = new URL(
      `/twirp/github.actions.results.api.v1.CacheService/${method}`,
      baseURL,
    );
    const response = await this.requester({
      url,
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Accept-Encoding': 'identity',
        Authorization: `Bearer ${token}`,
        'Content-Length': String(body.length),
        'Content-Type': 'application/json',
        'User-Agent': 'cataggar-debz-download-action',
      },
      body,
      maxBytes: CACHE_API_MAX_BYTES,
      timeoutMs: CACHE_CONTROL_TIMEOUT_MS,
    });
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw new DownloadActionError(
        `Actions cache ${method} failed with HTTP ${response.statusCode}`,
      );
    }
    try {
      return record(
        JSON.parse(response.body.toString('utf8')),
        `Actions cache ${method} response`,
      );
    } catch (error) {
      if (error instanceof DownloadActionError) throw error;
      throw new DownloadActionError(`Actions cache ${method} returned invalid JSON`);
    }
  }
}

export const defaultCache: CacheAdapter = new ActionsCacheV2();

export async function createTransferArea(runnerTemp: string): Promise<TransferArea> {
  const resolvedTemp = await realpath(runnerTemp);
  if (resolvedTemp !== path.resolve(runnerTemp)) {
    throw new DownloadActionError('RUNNER_TEMP must not traverse a symbolic link');
  }
  const root = await mkdtemp(path.join(resolvedTemp, 'debz-cache-transfer-'));
  await chmod(root, 0o700);
  if ((await realpath(root)) !== root) {
    throw new DownloadActionError('cache transfer directory is not canonical');
  }
  return {
    root,
    restoredArchive: path.join(root, 'restored.dbzcache'),
    exportArchive: path.join(root, 'export.dbzcache'),
    async cleanup() {
      await rm(root, { recursive: true, force: true });
    },
  };
}

async function validateArchiveFile(
  filename: string,
  maximumBytes: number,
  expectedBytes?: number,
): Promise<number> {
  const info = await lstat(filename);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new DownloadActionError('cache archive staging path is not a regular file');
  }
  const resolved = await realpath(filename);
  if (resolved !== path.resolve(filename)) {
    throw new DownloadActionError('cache archive staging path traverses a symbolic link');
  }
  const details = await stat(filename);
  if (
    !Number.isSafeInteger(details.size) ||
    details.size <= 0 ||
    details.size > maximumBytes ||
    (expectedBytes !== undefined && details.size !== expectedBytes)
  ) {
    throw new DownloadActionError('cache archive staging file has an invalid size');
  }
  return details.size;
}

function validateServiceURL(value: string): URL {
  const url = new URL(value);
  if (
    url.protocol !== 'https:' ||
    url.port !== '' ||
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== '' ||
    !url.hostname.endsWith(RESULTS_HOST_SUFFIX)
  ) {
    throw new DownloadActionError(
      'Actions cache service URL is not an approved HTTPS results endpoint',
    );
  }
  return url;
}

function validateBlobURL(value: string): URL {
  const url = new URL(value);
  if (
    url.protocol !== 'https:' ||
    url.port !== '' ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== '' ||
    !url.hostname.endsWith(BLOB_HOST_SUFFIX)
  ) {
    throw new DownloadActionError('cache service returned an unapproved blob URL');
  }
  return url;
}

function cacheMode(environment: NodeJS.ProcessEnv): string {
  return (environment.ACTIONS_CACHE_MODE ?? '').trim().toLowerCase();
}

function cacheReadable(environment: NodeJS.ProcessEnv): boolean {
  const mode = cacheMode(environment);
  return mode !== 'none' && mode !== 'write-only';
}

function cacheWritable(environment: NodeJS.ProcessEnv): boolean {
  const mode = cacheMode(environment);
  return mode !== 'none' && mode !== 'read';
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new DownloadActionError(`${label} is not an object`);
  }
  return value as Record<string, unknown>;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function responseString(
  response: Record<string, unknown>,
  snakeCase: string,
  camelCase: string,
): string | undefined {
  return optionalString(response[snakeCase]) ?? optionalString(response[camelCase]);
}
