import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { TrustedRoot } from '@sigstore/protobuf-specs';

import {
  certificateIdentity,
  certificateIdentityPattern,
  validateProvenanceStatement,
  verifyProvenance,
  verifySigstoreBundle,
  type ProvenanceExpectation,
} from '../src/provenance.js';

const fixtureDirectory = path.join(process.cwd(), '__tests__', 'fixtures');
const expected: ProvenanceExpectation = {
  tag: 'v0.2.0',
  assetName: 'debz-0.2.0-linux-x64.tar.gz',
  digest: '80c63abc6ba357733440de57b1f93441b1ac32d6a65da7dbfca4ccb78e1935ae',
  commit: '03997776cf28092bcc4a8bc04bd3cc63fbe7a124',
};

async function loadFixtures(): Promise<{ bundle: Record<string, unknown>; root: TrustedRoot }> {
  const [bundleText, rootText] = await Promise.all([
    readFile(path.join(fixtureDirectory, 'v0.2.0-x64.bundle.json'), 'utf8'),
    readFile(path.join(fixtureDirectory, 'sigstore-trusted-root.json'), 'utf8'),
  ]);
  return {
    bundle: JSON.parse(bundleText) as Record<string, unknown>,
    root: TrustedRoot.fromJSON(JSON.parse(rootText)),
  };
}

function payload(bundle: Record<string, unknown>): Record<string, unknown> {
  const envelope = bundle.dsseEnvelope as Record<string, unknown>;
  return JSON.parse(Buffer.from(envelope.payload as string, 'base64').toString('utf8')) as Record<
    string,
    unknown
  >;
}

function replacePayload(
  bundle: Record<string, unknown>,
  statement: Record<string, unknown>,
): Record<string, unknown> {
  const result = structuredClone(bundle);
  const envelope = result.dsseEnvelope as Record<string, unknown>;
  envelope.payload = Buffer.from(JSON.stringify(statement)).toString('base64');
  return result;
}

test('captured multi-subject GitHub provenance verifies cryptographically and by policy', async () => {
  const fixtures = await loadFixtures();
  verifySigstoreBundle(fixtures.bundle, fixtures.root, expected);
  validateProvenanceStatement(fixtures.bundle, expected);
});

test('certificate identity policy matches only the exact escaped SAN', () => {
  const identity = certificateIdentity(expected.tag);
  const pattern = certificateIdentityPattern(expected.tag);
  assert.match(identity, pattern);
  for (const candidate of [
    identity.replace('release.yml', 'releaseXyml'),
    identity.replace('/.github/', '/Xgithub/'),
    `prefix-${identity}`,
    `${identity}-suffix`,
  ]) {
    assert.doesNotMatch(candidate, pattern);
  }

  const metadataTag = 'v1.2.3+build.1';
  const metadataIdentity = certificateIdentity(metadataTag);
  const metadataPattern = certificateIdentityPattern(metadataTag);
  assert.match(metadataIdentity, metadataPattern);
  assert.doesNotMatch(
    metadataIdentity.replace('v1.2.3+build.1', 'v1x2x3-buildX1'),
    metadataPattern,
  );
});

test('tampering with a signed provenance payload invalidates its signature', async () => {
  const fixtures = await loadFixtures();
  const statement = payload(fixtures.bundle);
  const subjects = statement.subject as Array<Record<string, unknown>>;
  (subjects[1]?.digest as Record<string, unknown>).sha256 = '0'.repeat(64);
  const tampered = replacePayload(fixtures.bundle, statement);
  assert.throws(
    () => verifySigstoreBundle(tampered, fixtures.root, expected),
    /signature|verification/i,
  );
});

test('cryptographic policy rejects a different repository or workflow identity', async () => {
  const fixtures = await loadFixtures();
  assert.throws(
    () =>
      verifySigstoreBundle(
        fixtures.bundle,
        fixtures.root,
        { ...expected, tag: 'v0.2.1' },
      ),
    /identity|alternative name|policy/i,
  );
});

test('provenance policy rejects wrong subject, repository, workflow, ref, commit, and build type', async () => {
  const { bundle } = await loadFixtures();
  const mutations: Array<(statement: Record<string, unknown>) => void> = [
    (statement) => {
      const subjects = statement.subject as Array<Record<string, unknown>>;
      (subjects[1]?.digest as Record<string, unknown>).sha256 = '0'.repeat(64);
    },
    (statement) => {
      const predicate = statement.predicate as Record<string, unknown>;
      const definition = predicate.buildDefinition as Record<string, unknown>;
      const external = definition.externalParameters as Record<string, unknown>;
      (external.workflow as Record<string, unknown>).repository = 'https://github.com/other/repo';
    },
    (statement) => {
      const predicate = statement.predicate as Record<string, unknown>;
      const definition = predicate.buildDefinition as Record<string, unknown>;
      const external = definition.externalParameters as Record<string, unknown>;
      (external.workflow as Record<string, unknown>).path = '.github/workflows/other.yml';
    },
    (statement) => {
      const predicate = statement.predicate as Record<string, unknown>;
      const definition = predicate.buildDefinition as Record<string, unknown>;
      const external = definition.externalParameters as Record<string, unknown>;
      (external.workflow as Record<string, unknown>).ref = 'refs/heads/main';
    },
    (statement) => {
      const predicate = statement.predicate as Record<string, unknown>;
      const definition = predicate.buildDefinition as Record<string, unknown>;
      const dependencies = definition.resolvedDependencies as Array<Record<string, unknown>>;
      (dependencies[0]?.digest as Record<string, unknown>).gitCommit = '0'.repeat(40);
    },
    (statement) => {
      const predicate = statement.predicate as Record<string, unknown>;
      const definition = predicate.buildDefinition as Record<string, unknown>;
      definition.buildType = 'https://example.invalid/build';
    },
  ];
  for (const mutate of mutations) {
    const statement = payload(bundle);
    mutate(statement);
    assert.throws(
      () => validateProvenanceStatement(replacePayload(bundle, statement), expected),
      /attestation/,
    );
  }
});

test('multiple bundles are accepted only when one is fully valid', async () => {
  const fixtures = await loadFixtures();
  await verifyProvenance(
    [{ malformed: true }, fixtures.bundle],
    expected,
    '/unused',
    async () => fixtures.root,
  );
  await assert.rejects(
    verifyProvenance(
      [{ malformed: true }],
      expected,
      '/unused',
      async () => fixtures.root,
    ),
    /no cryptographically valid/,
  );
});

test('TUF failure is fail-closed and points to the explicit trusted-SHA mode', async () => {
  const fixtures = await loadFixtures();
  await assert.rejects(
    verifyProvenance(
      [fixtures.bundle],
      expected,
      '/unused',
      async () => {
        throw new Error('offline');
      },
    ),
    /through TUF.*provide sha256/,
  );
});
