import * as cache from '@actions/cache';
import * as core from '@actions/core';
import { lstat, realpath } from 'node:fs/promises';
import path from 'node:path';

export interface CacheAdapter {
  isFeatureAvailable(): boolean;
  restore(
    path: string,
    primaryKey: string,
    restorePrefix: string,
  ): Promise<string | undefined>;
  save(path: string, primaryKey: string): Promise<void>;
}

export class ActionsCache implements CacheAdapter {
  isFeatureAvailable(): boolean {
    return cache.isFeatureAvailable();
  }

  async restore(
    cachePath: string,
    primaryKey: string,
    restorePrefix: string,
  ): Promise<string | undefined> {
    try {
      return await inCacheParent(cachePath, async (cacheLeaf) =>
        cache.restoreCache(
          [cacheLeaf],
          primaryKey,
          [restorePrefix],
          {},
          false,
        ),
      );
    } catch {
      core.warning(
        'GitHub Actions cache restore failed; debz will verify any remaining objects and continue as a miss',
      );
      return undefined;
    }
  }

  async save(cachePath: string, primaryKey: string): Promise<void> {
    try {
      await inCacheParent(cachePath, async (cacheLeaf) => {
        await cache.saveCache([cacheLeaf], primaryKey, {}, false);
      });
    } catch {
      // Cache publication is an optimization. This also makes the immutable-key
      // reservation race between concurrent successful jobs benign.
      core.warning(
        'GitHub Actions cache save was unavailable or the immutable key already exists',
      );
    }
  }
}

export const defaultCache = new ActionsCache();

async function inCacheParent<T>(
  cachePath: string,
  operation: (cacheLeaf: string) => Promise<T>,
): Promise<T> {
  const parent = path.dirname(cachePath);
  const leaf = path.basename(cachePath);
  if (leaf !== 'objects') {
    throw new Error('cache path must end in the package object directory');
  }
  if ((await realpath(parent)) !== path.resolve(parent)) {
    throw new Error('cache parent must not traverse a symbolic link');
  }
  const info = await lstat(cachePath);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error('cache object path must be a regular directory');
  }
  const previous = process.cwd();
  process.chdir(parent);
  try {
    return await operation(leaf);
  } finally {
    process.chdir(previous);
  }
}
