import Ajv2020 from 'ajv/dist/2020.js';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import type {
  Base64Url,
  DecimalU64,
  Ed25519PublicKeyBytes,
  OperationId,
  Sha256Hex,
  SyncOperationV1,
  X25519PublicKeyBytes,
} from './bindings';

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

const workspace = resolve(import.meta.dirname, '../../..');
const load = (path: string) => JSON.parse(readFileSync(resolve(workspace, path), 'utf8'));

describe('protocol schemas', () => {
  it('validates every MCP input and output fixture with Draft 2020-12', () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
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
    const ajv = new Ajv2020({ strict: true });
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
    const ajv = new Ajv2020({ strict: true });
    const validate = ajv.compile(load('schemas/context_relay_search-input-v1.json'));
    expect(validate({ query: 'needle' }), ajv.errorsText(validate.errors)).toBe(true);
    expect(validate({ query: ' \t\n' })).toBe(false);
  });

  it('validates package and export fixtures', () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
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
