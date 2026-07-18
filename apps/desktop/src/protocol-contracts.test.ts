import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import type {
  Base64Url,
  DecimalU64,
  Ed25519PublicKeyBytes,
  MemoryRecord,
  OperationId,
  PairingId,
  RecordId,
  SetupPlan,
  Sha256Hex,
  SyncOperationV1,
  TaskRecord,
  X25519PublicKeyBytes,
} from './bindings';
import {
  assertBase64UrlBytes,
  assertSha256Hex,
  createProtocolSchemaValidator,
} from './protocol-validation';

type Assert<T extends true> = T;
type OperationBrandIsPreserved = Assert<OperationId extends SyncOperationV1['operationId'] ? true : false>;
type DigestBrandIsPreserved = Assert<Sha256Hex extends SyncOperationV1['previousDeviceHash'] ? true : false>;
type BytesBrandIsPreserved = Assert<Base64Url extends SyncOperationV1['ciphertext'] ? true : false>;
type DecimalBrandIsPreserved = Assert<DecimalU64 extends SyncOperationV1['deviceSequence'] ? true : false>;
type BindingBrandAssertions = [
  OperationBrandIsPreserved,
  DigestBrandIsPreserved,
  BytesBrandIsPreserved,
  DecimalBrandIsPreserved,
];
const bindingBrandAssertions: BindingBrandAssertions = [true, true, true, true];
void bindingBrandAssertions;
// @ts-expect-error UUID fields reject plain strings.
const invalidUuid: SyncOperationV1['operationId'] = '018f22e2-79b0-7cc8-98c4-dc0c0c07398f';
void invalidUuid;
function assertKeySeparation(signingKey: Ed25519PublicKeyBytes) {
  // @ts-expect-error Ed25519 signing keys cannot be used as X25519 wrapping keys.
  const wrappingKey: X25519PublicKeyBytes = signingKey;
  void wrappingKey;
}
void assertKeySeparation;
function assertPairingIdSeparation(pairingId: PairingId) {
  // @ts-expect-error Pairing IDs cannot be used as record IDs.
  const recordId: RecordId = pairingId;
  void recordId;
}
void assertPairingIdSeparation;

const workspace = resolve(import.meta.dirname, '../../..');
const load = (path: string) => JSON.parse(readFileSync(resolve(workspace, path), 'utf8'));

describe('protocol schemas', () => {
  it('validates every MCP input and output fixture with Draft 2020-12', () => {
    const ajv = createProtocolSchemaValidator();
    const validInputs = load('crates/protocol/tests/fixtures/mcp-valid.json');
    const invalidInputs = load('crates/protocol/tests/fixtures/mcp-invalid.json');
    const validOutputs = load('crates/protocol/tests/fixtures/mcp-output-valid.json');
    const invalidOutputs = load('crates/protocol/tests/fixtures/mcp-output-invalid.json');
    for (const name of Object.keys(validInputs)) {
      const input = ajv.compile(load(`schemas/${name}-input-v1.json`));
      const output = ajv.compile(load(`schemas/${name}-output-v1.json`));
      expect(input(validInputs[name]), `${name} valid input: ${ajv.errorsText(input.errors)}`).toBe(true);
      expect(input(invalidInputs[name]), `${name} invalid input`).toBe(false);
      expect(output(validOutputs[name]), `${name} valid output: ${ajv.errorsText(output.errors)}`).toBe(true);
      expect(output(invalidOutputs[name]), `${name} invalid output`).toBe(false);
    }
  });

  it('accepts only correctly paired upsert task revision options', () => {
    const ajv = createProtocolSchemaValidator();
    const validate = ajv.compile(load('schemas/context_relay_upsert_task-input-v1.json'));
    const base = {
      operationId: '018f22e2-79b0-7cc8-98c4-dc0c0c07398f',
      projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c07398f',
      title: 'Task',
      bodyMarkdown: 'Body',
      status: 'open',
    };
    const id = '018f22e2-79b0-7cc8-98c4-dc0c0c07398f';
    expect(validate(base), ajv.errorsText(validate.errors)).toBe(true);
    expect(validate({ ...base, taskId: null, expectedRevision: null }), ajv.errorsText(validate.errors)).toBe(true);
    expect(validate({ ...base, taskId: id, expectedRevision: id }), ajv.errorsText(validate.errors)).toBe(true);
    expect(validate({ ...base, taskId: id, expectedRevision: null })).toBe(false);
    expect(validate({ ...base, taskId: null, expectedRevision: id })).toBe(false);
  });

  it('applies non-whitespace text patterns as regexes', () => {
    const ajv = createProtocolSchemaValidator();
    const validate = ajv.compile(load('schemas/context_relay_search-input-v1.json'));
    expect(validate({ query: 'needle' }), ajv.errorsText(validate.errors)).toBe(true);
    expect(validate({ query: ' \t\n' })).toBe(false);
  });

  it('enforces Rust UTF-8 byte limits for non-ASCII text', () => {
    const ajv = createProtocolSchemaValidator();
    const schema = load('schemas/context_relay_remember-input-v1.json');
    expect(schema.properties.title['x-utf8-maxBytes']).toBe(512);
    const validate = ajv.compile(schema);
    const fixture = load('crates/protocol/tests/fixtures/mcp-valid.json').context_relay_remember;
    expect(validate({ ...fixture, title: '\u00e9'.repeat(300) })).toBe(false);
  });

  it('accepts Context Relay projects without repository metadata', () => {
    const ajv = createProtocolSchemaValidator();
    const validate = ajv.compile(load('schemas/context_relay_create_handoff-output-v1.json'));
    const fixture = load('crates/protocol/tests/fixtures/mcp-output-valid.json').context_relay_create_handoff;
    fixture.payload.project = {
      projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c07398f',
      githubRepositoryId: null,
      gitRemoteFingerprint: null,
      monorepoSubdirectory: null,
      name: 'Relay project',
    };
    expect(validate(fixture), ajv.errorsText(validate.errors)).toBe(true);
    fixture.payload.project.githubRepositoryId = '0';
    expect(validate(fixture)).toBe(false);
    fixture.payload.project.githubRepositoryId = null;
    fixture.payload.project.gitRemoteFingerprint = '00';
    expect(validate(fixture)).toBe(false);
    fixture.payload.project.gitRemoteFingerprint = null;
    fixture.payload.project.monorepoSubdirectory = '\u00e9'.repeat(300);
    expect(validate(fixture)).toBe(false);
  });

  it('round-trips Rust runtime fixtures and rejects malformed fixed-size primitives', () => {
    const fixture = load('crates/protocol/tests/fixtures/runtime-contracts-v1.json') as {
      memory: MemoryRecord;
      task: TaskRecord;
      setupPlan: SetupPlan;
      syncOperation: SyncOperationV1;
    };
    for (const value of Object.values(fixture)) {
      expect(JSON.parse(JSON.stringify(value))).toEqual(value);
    }

    const operation = fixture.syncOperation;
    expect(() => {
      assertSha256Hex(operation.previousDeviceHash);
      assertBase64UrlBytes(operation.nonce, 24);
      assertBase64UrlBytes(operation.signature, 64);
    }).not.toThrow();
    expect(() => assertSha256Hex('00')).toThrow();
    expect(() => assertBase64UrlBytes('AQ', 24)).toThrow();
    expect(() => assertBase64UrlBytes('AQ', 64)).toThrow();
  });

  it('validates package and export fixtures', () => {
    const ajv = createProtocolSchemaValidator();
    for (const contract of ['package', 'export']) {
      const validate = ajv.compile(load(`schemas/context-relay-${contract}-v1.json`));
      expect(
        validate(load(`crates/protocol/tests/fixtures/${contract}-v1-valid.json`)),
        ajv.errorsText(validate.errors),
      ).toBe(true);
      expect(validate(load(`crates/protocol/tests/fixtures/${contract}-v1-invalid.json`))).toBe(false);
    }
  });
});
