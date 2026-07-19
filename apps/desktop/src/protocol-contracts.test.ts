import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import type {
  Base64Url,
  CompletionEvidenceInput,
  DecimalU64,
  Ed25519PublicKeyBytes,
  GetOutput,
  HandoffPayload,
  ListTasksInput,
  MemoryRecord,
  OperationId,
  PairingId,
  RecordId,
  SearchInput,
  SetupPlan,
  Sha256Hex,
  StatusOutput,
  SyncOperationV1,
  TaskRecord,
  UpsertTaskInput,
  WireNativeValue,
  X25519PublicKeyBytes,
} from './bindings';
import * as protocolValidation from './protocol-validation';

const { createProtocolSchemaValidator } = protocolValidation;
type Assert<T extends true> = T;
type OperationBrandIsPreserved = Assert<OperationId extends SyncOperationV1['operationId'] ? true : false>;
type DigestBrandIsPreserved = Assert<Sha256Hex extends SyncOperationV1['previousDeviceHash'] ? true : false>;
type BytesBrandIsPreserved = Assert<Base64Url extends SyncOperationV1['ciphertext'] ? true : false>;
type DecimalBrandIsPreserved = Assert<DecimalU64 extends SyncOperationV1['deviceSequence'] ? true : false>;
const bindingBrandAssertions: [OperationBrandIsPreserved, DigestBrandIsPreserved, BytesBrandIsPreserved, DecimalBrandIsPreserved] = [true, true, true, true];
void bindingBrandAssertions;
type IsOptional<T, K extends keyof T> = Pick<T, never> extends Pick<T, K> ? true : false;
type IsRequired<T, K extends keyof T> = IsOptional<T, K> extends true ? false : true;
const optionalBindingAssertions: [
  Assert<IsOptional<SearchInput, 'scope'>>,
  Assert<IsOptional<SearchInput, 'limit'>>,
  Assert<IsOptional<ListTasksInput, 'status'>>,
  Assert<IsOptional<UpsertTaskInput, 'taskId'>>,
  Assert<IsOptional<UpsertTaskInput, 'expectedRevision'>>,
  Assert<IsOptional<CompletionEvidenceInput, 'reference'>>,
  Assert<IsOptional<WireNativeValue, 'display'>>,
] = [true, true, true, true, true, true, true];
const requiredNullableBindingAssertions: [
  Assert<IsRequired<GetOutput, 'record'>>,
  Assert<IsRequired<HandoffPayload, 'project'>>,
  Assert<IsRequired<StatusOutput, 'resolvedProject'>>,
  Assert<IsRequired<SyncOperationV1, 'projectId'>>,
] = [true, true, true, true];
void optionalBindingAssertions;
void requiredNullableBindingAssertions;
function assertExplicitNullOptionalBindings(operationId: OperationId, bytesValue: Base64Url) {
  const search: SearchInput = { query: 'needle', scope: null, limit: null };
  const list: ListTasksInput = { status: null };
  const upsert: UpsertTaskInput = {
    operationId,
    taskId: null,
    title: 'Task',
    bodyMarkdown: 'Body',
    status: 'open',
    expectedRevision: null,
  };
  const evidence: CompletionEvidenceInput = { summary: 'Done', kind: 'result', reference: null };
  const nativeValue: WireNativeValue = { platform: 'macos', bytes: bytesValue, display: null };
  void [search, list, upsert, evidence, nativeValue];
}
void assertExplicitNullOptionalBindings;
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
type GuardName = 'assertMemoryRecord' | 'assertTaskRecord' | 'assertSetupPlan' | 'assertSyncOperationV1' | 'assertMemoryCreateJsonRpcRequestV1';
const guards: Record<GuardName, (value: unknown) => void> = {
  assertMemoryRecord: protocolValidation.assertMemoryRecord,
  assertTaskRecord: protocolValidation.assertTaskRecord,
  assertSetupPlan: protocolValidation.assertSetupPlan,
  assertSyncOperationV1: protocolValidation.assertSyncOperationV1,
  assertMemoryCreateJsonRpcRequestV1: protocolValidation.assertMemoryCreateJsonRpcRequestV1,
};
const rejectsWith = (guard: (value: unknown) => void, value: unknown) => expect(() => guard(value)).toThrow();
const rejects = (name: GuardName, value: unknown) => rejectsWith(guards[name], value);
const mutate = <T>(value: T, change: (copy: T) => void) => { const copy = structuredClone(value); change(copy); return copy; };
const without = (value: object, field: string) => { const copy = structuredClone(value) as Record<string, unknown>; delete copy[field]; return copy; };
const parentAtPath = (value: unknown, path: readonly PropertyKey[]) => {
  let parent = value as Record<PropertyKey, unknown>;
  for (const key of path.slice(0, -1)) parent = parent[key] as Record<PropertyKey, unknown>;
  return parent;
};
const withoutPath = (value: unknown, path: readonly PropertyKey[]) => {
  const copy = structuredClone(value);
  delete parentAtPath(copy, path)[path.at(-1)!];
  return copy;
};
const nullAtPath = (value: unknown, path: readonly PropertyKey[]) => {
  const copy = structuredClone(value);
  parentAtPath(copy, path)[path.at(-1)!] = null;
  return copy;
};

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
    const base = { operationId: '018f22e2-79b0-7cc8-98c4-dc0c0c07398f', title: 'Task', bodyMarkdown: 'Body', status: 'open' };
    const id = '018f22e2-79b0-7cc8-98c4-dc0c0c07398f';
    expect(validate(base)).toBe(true);
    expect(validate({ ...base, taskId: null, expectedRevision: null })).toBe(true);
    expect(validate({ ...base, taskId: null })).toBe(true);
    expect(validate({ ...base, expectedRevision: null })).toBe(true);
    expect(validate({ ...base, taskId: id, expectedRevision: id })).toBe(true);
    expect(validate({ ...base, taskId: id, expectedRevision: null })).toBe(false);
    expect(validate({ ...base, taskId: null, expectedRevision: id })).toBe(false);
  });

  it('accepts omitted or explicit null optional MCP input fields', () => {
    const ajv = createProtocolSchemaValidator();
    const inputs = load('crates/protocol/tests/fixtures/mcp-valid.json');
    const cases = [
      ['context_relay_search', { query: 'needle' }, { query: 'needle', scope: null, limit: null }],
      ['context_relay_list_tasks', {}, { status: null }],
      [
        'context_relay_complete_task',
        inputs.context_relay_complete_task,
        {
          ...inputs.context_relay_complete_task,
          evidence: [{ ...inputs.context_relay_complete_task.evidence[0], reference: null }],
        },
      ],
    ] as const;
    for (const [name, omitted, explicitNull] of cases) {
      const validate = ajv.compile(load(`schemas/${name}-input-v1.json`));
      expect(validate(omitted), `${name} omitted: ${ajv.errorsText(validate.errors)}`).toBe(true);
      expect(validate(explicitNull), `${name} null: ${ajv.errorsText(validate.errors)}`).toBe(true);
    }
  });

  it('applies non-whitespace text patterns and Rust UTF-8 byte limits', () => {
    const ajv = createProtocolSchemaValidator();
    const search = ajv.compile(load('schemas/context_relay_search-input-v1.json'));
    expect(search({ query: 'needle' })).toBe(true);
    expect(search({ query: ' \t\n' })).toBe(false);
    const schema = load('schemas/context_relay_remember-input-v1.json');
    const remember = ajv.compile(schema);
    const fixture = load('crates/protocol/tests/fixtures/mcp-valid.json').context_relay_remember;
    expect(remember({ ...fixture, title: '\u00e9'.repeat(300) })).toBe(false);
  });

  it('accepts Context Relay projects without repository metadata', () => {
    const ajv = createProtocolSchemaValidator();
    const schema = load('schemas/context_relay_create_handoff-output-v1.json');
    const pathPattern = schema.properties.payload.properties.project.oneOf[1].properties.monorepoSubdirectory.oneOf[1].pattern;
    expect(pathPattern).toContain('\\u2028\\u2029');
    const validate = ajv.compile(schema);
    const fixture = load('crates/protocol/tests/fixtures/mcp-output-valid.json').context_relay_create_handoff;
    fixture.payload.project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c07398f', githubRepositoryId: null, gitRemoteFingerprint: null, monorepoSubdirectory: null, name: 'Relay project' };
    expect(validate(fixture)).toBe(true);
    fixture.payload.project.githubRepositoryId = '0'; expect(validate(fixture)).toBe(false);
    fixture.payload.project.githubRepositoryId = null; fixture.payload.project.gitRemoteFingerprint = '00'; expect(validate(fixture)).toBe(false);
    fixture.payload.project.gitRemoteFingerprint = null; fixture.payload.project.monorepoSubdirectory = '\u00e9'.repeat(300); expect(validate(fixture)).toBe(false);
    for (const path of ['a//b', 'a/', 'a\u007fb', 'a\u0085b', 'a\u009fb', 'a\u2028b', 'a\u2029b']) {
      fixture.payload.project.monorepoSubdirectory = path;
      expect(validate(fixture), `accepted ${JSON.stringify(path)}`).toBe(false);
    }
    const nullableProject = {
      projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c07398f',
      githubRepositoryId: null,
      gitRemoteFingerprint: null,
      monorepoSubdirectory: null,
      name: 'Relay project',
    };
    for (const field of ['githubRepositoryId', 'gitRemoteFingerprint', 'monorepoSubdirectory'] as const) {
      fixture.payload.project = structuredClone(nullableProject);
      expect(validate(fixture), `explicit null ${field}: ${ajv.errorsText(validate.errors)}`).toBe(true);
      delete fixture.payload.project[field];
      expect(validate(fixture), `omitted ${field}`).toBe(false);
    }
  });

  it('requires nullable output keys while accepting explicit null', () => {
    const ajv = createProtocolSchemaValidator();
    const outputs = load('crates/protocol/tests/fixtures/mcp-output-valid.json');
    for (const [name, path] of [
      ['context_relay_get', ['record']],
      ['context_relay_create_handoff', ['payload', 'project']],
      ['context_relay_status', ['resolvedProject']],
      ['context_relay_remember', ['memory', 'provenance', 'harness']],
      ['context_relay_remember', ['memory', 'provenance', 'source']],
      ['context_relay_complete_task', ['task', 'evidence', 0, 'reference']],
    ] as const) {
      const validate = ajv.compile(load(`schemas/${name}-output-v1.json`));
      const explicitNull = nullAtPath(outputs[name], path);
      expect(validate(explicitNull), `${name} explicit null: ${ajv.errorsText(validate.errors)}`).toBe(true);
      expect(validate(withoutPath(outputs[name], path)), `${name} omitted ${path.join('.')}`).toBe(false);
    }
  });

  it('accepts only status protocol ranges containing v1.0', () => {
    const ajv = createProtocolSchemaValidator();
    const validate = ajv.compile(load('schemas/context_relay_status-output-v1.json'));
    const fixture = load('crates/protocol/tests/fixtures/mcp-output-valid.json').context_relay_status;
    expect(validate(fixture), ajv.errorsText(validate.errors)).toBe(true);
    for (const protocol of [
      { min: { major: 2, minor: 0 }, max: { major: 2, minor: 0 } },
      { min: { major: 1, minor: 1 }, max: { major: 1, minor: 2 } },
      { min: { major: 1, minor: 1 }, max: { major: 1, minor: 0 } },
    ]) {
      expect(validate({ ...fixture, protocol }), JSON.stringify(protocol)).toBe(false);
    }
  });

  it('bounds MCP HLC physical milliseconds to canonical u64 text', () => {
    const ajv = createProtocolSchemaValidator();
    const validate = ajv.compile(load('schemas/context_relay_remember-output-v1.json'));
    const fixture = load('crates/protocol/tests/fixtures/mcp-output-valid.json').context_relay_remember;
    fixture.memory.createdHlc.physicalMs = '18446744073709551615';
    expect(validate(fixture), ajv.errorsText(validate.errors)).toBe(true);
    fixture.memory.createdHlc.physicalMs = '18446744073709551616';
    expect(validate(fixture)).toBe(false);
  });

  it('bounds MCP GitHub repository IDs to positive canonical u64 text', () => {
    const ajv = createProtocolSchemaValidator();
    const validate = ajv.compile(load('schemas/context_relay_create_handoff-output-v1.json'));
    const fixture = load('crates/protocol/tests/fixtures/mcp-output-valid.json').context_relay_create_handoff;
    fixture.payload.project = {
      projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c07398f',
      githubRepositoryId: '18446744073709551615',
      gitRemoteFingerprint: null,
      monorepoSubdirectory: null,
      name: 'Relay project',
    };
    expect(validate(fixture), ajv.errorsText(validate.errors)).toBe(true);
    fixture.payload.project.githubRepositoryId = '18446744073709551616';
    expect(validate(fixture)).toBe(false);
  });

  it('rejects terminal, newline, and bidi controls in native display text', () => {
    const plan = load('crates/protocol/tests/fixtures/runtime-contracts-v1.json').setupPlan as SetupPlan;
    for (const display of ['line\nbreak', '\u001b[31m', 'safe\u202etext']) {
      rejectsWith(
        protocolValidation.assertSetupPlan,
        mutate(plan, (copy) => Object.assign(copy.executablePath, { display })),
      );
    }
  });

  it('accepts omitted or explicit null native display text', () => {
    const plan = load('crates/protocol/tests/fixtures/runtime-contracts-v1.json').setupPlan as SetupPlan;
    const omitted = mutate(plan, (copy) => { delete copy.executablePath.display; });
    const explicitNull = mutate(plan, (copy) => { copy.executablePath.display = null; });
    expect(() => protocolValidation.assertSetupPlan(omitted)).not.toThrow();
    expect(() => protocolValidation.assertSetupPlan(explicitNull)).not.toThrow();
  });

  it('matches Rust setup-plan adapter bounds', () => {
    const plan = load('crates/protocol/tests/fixtures/runtime-contracts-v1.json').setupPlan as SetupPlan;
    const native = { platform: 'macos', bytes: 'YQ', display: 'a' };
    const sha = '0505050505050505050505050505050505050505050505050505050505050505';
    const dependency = { name: 'dependency', version: '1', digest: sha, immutableSourceRef: 'source' };
    const artifact = { packageId: plan.planId, immutableSourceRef: 'source', resolvedCommit: 'a'.repeat(40), archiveDigest: sha, artifactPath: native, artifactDigest: sha, dependencies: [] };
    const collections = [
      mutate(plan, (copy) => Object.assign(copy, { targetScopes: Array.from({ length: 1025 }, () => ({ scope: 'global' })) })),
      mutate(plan, (copy) => Object.assign(copy, { expectedNativeDigests: Array.from({ length: 1025 }, () => ({ target: native, expectedDigest: null })) })),
      mutate(plan, (copy) => Object.assign(copy, { semanticChanges: Array.from({ length: 1025 }, () => ({ class: 'create', target: 'target', summary: 'summary' })) })),
      mutate(plan, (copy) => Object.assign(copy, { cliOperations: Array.from({ length: 1025 }, () => ({ executable: native, arguments: [], timeoutMs: 1 })) })),
      mutate(plan, (copy) => Object.assign(copy, { packageArtifacts: Array.from({ length: 1025 }, () => artifact) })),
      mutate(plan, (copy) => Object.assign(copy, { cliOperations: [{ executable: native, arguments: Array.from({ length: 1025 }, () => native), timeoutMs: 1 }] })),
      mutate(plan, (copy) => Object.assign(copy, { packageArtifacts: [{ ...artifact, dependencies: Array.from({ length: 1025 }, () => dependency) }] })),
      mutate(plan, (copy) => Object.assign(copy, { permissionDelta: { added: Array.from({ length: 1025 }, () => 'read'), removed: [] } })),
      mutate(plan, (copy) => Object.assign(copy, { permissionDelta: { added: [], removed: Array.from({ length: 1025 }, () => 'read') } })),
      mutate(plan, (copy) => Object.assign(copy, { networkDelta: { added: Array.from({ length: 1025 }, () => ({ scheme: 'https', host: 'example.com', port: 443 })), removed: [] } })),
      mutate(plan, (copy) => Object.assign(copy, { networkDelta: { added: [], removed: Array.from({ length: 1025 }, () => ({ scheme: 'https', host: 'example.com', port: 443 })) } })),
    ];
    for (const value of collections) rejectsWith(protocolValidation.assertSetupPlan, value);

    const tooLong = 'x'.repeat(16 * 1024 + 1);
    for (const value of [
      mutate(plan, (copy) => Object.assign(copy, { semanticChanges: [{ class: 'create', target: tooLong, summary: 'summary' }] })),
      mutate(plan, (copy) => Object.assign(copy, { semanticChanges: [{ class: 'create', target: 'target', summary: tooLong }] })),
      mutate(plan, (copy) => Object.assign(copy, { packageArtifacts: [{ ...artifact, immutableSourceRef: tooLong }] })),
    ]) rejectsWith(protocolValidation.assertSetupPlan, value);
  });

  it('rejects decimal u64 text longer than 20 digits', () => {
    const fixture = load('crates/protocol/tests/fixtures/runtime-contracts-v1.json');
    rejectsWith(protocolValidation.assertSetupPlan, mutate(fixture.setupPlan, (copy) => Object.assign(copy, { expiresAt: '1'.repeat(21) })));
    rejectsWith(protocolValidation.assertSyncOperationV1, mutate(fixture.syncOperation, (copy) => Object.assign(copy, { deviceSequence: '1'.repeat(21) })));
  });

  it('rejects every fixed-size branded field in the representative fixtures', () => {
    const fixture = load('crates/protocol/tests/fixtures/runtime-contracts-v1.json') as { memory: MemoryRecord; task: TaskRecord; setupPlan: SetupPlan; syncOperation: SyncOperationV1 };
    const invalidId = 'not-a-uuid';
    const cases: Array<[(value: unknown) => void, unknown]> = [
      [protocolValidation.assertMemoryRecord, mutate(fixture.memory, (copy) => Object.assign(copy, { id: invalidId }))],
      [protocolValidation.assertMemoryRecord, mutate(fixture.memory, (copy) => Object.assign(copy.provenance, { originDevice: invalidId }))],
      [protocolValidation.assertMemoryRecord, mutate(fixture.memory, (copy) => Object.assign(copy.provenance.createdHlc, { node: invalidId }))],
      [protocolValidation.assertMemoryRecord, mutate(fixture.memory, (copy) => Object.assign(copy, { revision: invalidId }))],
      [protocolValidation.assertMemoryRecord, mutate(fixture.memory, (copy) => Object.assign(copy.createdHlc, { node: invalidId }))],
      [protocolValidation.assertMemoryRecord, mutate(fixture.memory, (copy) => Object.assign(copy.updatedHlc, { node: invalidId }))],
      [protocolValidation.assertTaskRecord, mutate(fixture.task, (copy) => Object.assign(copy, { id: invalidId }))],
      [protocolValidation.assertTaskRecord, mutate(fixture.task, (copy) => Object.assign(copy, { projectId: invalidId }))],
      [protocolValidation.assertTaskRecord, mutate(fixture.task, (copy) => Object.assign(copy, { revision: invalidId }))],
      [protocolValidation.assertSetupPlan, mutate(fixture.setupPlan, (copy) => Object.assign(copy, { planId: invalidId }))],
      [protocolValidation.assertSetupPlan, mutate(fixture.setupPlan, (copy) => Object.assign(copy, { executableHash: '00' }))],
      [protocolValidation.assertSetupPlan, mutate(fixture.setupPlan, (copy) => Object.assign(copy, { scannerReportHash: '00' }))],
      [protocolValidation.assertSetupPlan, mutate(fixture.setupPlan, (copy) => Object.assign(copy, { rulesyncHash: '00' }))],
      [protocolValidation.assertSetupPlan, mutate(fixture.setupPlan, (copy) => Object.assign(copy, { batchHash: '00' }))],
      [protocolValidation.assertSyncOperationV1, mutate(fixture.syncOperation, (copy) => Object.assign(copy, { operationId: invalidId }))],
      [protocolValidation.assertSyncOperationV1, mutate(fixture.syncOperation, (copy) => Object.assign(copy, { accountId: invalidId }))],
      [protocolValidation.assertSyncOperationV1, mutate(fixture.syncOperation, (copy) => Object.assign(copy, { workspaceId: invalidId }))],
      [protocolValidation.assertSyncOperationV1, mutate(fixture.syncOperation, (copy) => Object.assign(copy, { projectId: invalidId }))],
      [protocolValidation.assertSyncOperationV1, mutate(fixture.syncOperation, (copy) => Object.assign(copy, { recordId: invalidId }))],
      [protocolValidation.assertSyncOperationV1, mutate(fixture.syncOperation, (copy) => Object.assign(copy, { deviceId: invalidId }))],
      [protocolValidation.assertSyncOperationV1, mutate(fixture.syncOperation, (copy) => Object.assign(copy.causalFrontier[0], { deviceId: invalidId }))],
      [protocolValidation.assertSyncOperationV1, mutate(fixture.syncOperation, (copy) => Object.assign(copy, { previousDeviceHash: '00' }))],
      [protocolValidation.assertSyncOperationV1, mutate(fixture.syncOperation, (copy) => Object.assign(copy, { nonce: 'AQ' }))],
      [protocolValidation.assertSyncOperationV1, mutate(fixture.syncOperation, (copy) => Object.assign(copy, { ciphertextHash: '00' }))],
      [protocolValidation.assertSyncOperationV1, mutate(fixture.syncOperation, (copy) => Object.assign(copy.blobRefs[0], { digest: '00' }))],
      [protocolValidation.assertSyncOperationV1, mutate(fixture.syncOperation, (copy) => Object.assign(copy.createdHlc, { node: invalidId }))],
      [protocolValidation.assertSyncOperationV1, mutate(fixture.syncOperation, (copy) => Object.assign(copy, { signature: 'AQ' }))],
    ];
    for (const [guard, value] of cases) rejectsWith(guard, value);
  });

  it('runtime-validates every fixture field and rejects malformed nested values', () => {
    const fixture = load('crates/protocol/tests/fixtures/runtime-contracts-v1.json') as { memory: MemoryRecord; task: TaskRecord; setupPlan: SetupPlan; syncOperation: SyncOperationV1 };
    const contracts = [['assertMemoryRecord', fixture.memory], ['assertTaskRecord', fixture.task], ['assertSetupPlan', fixture.setupPlan], ['assertSyncOperationV1', fixture.syncOperation]] as const;
    for (const [guard, value] of contracts) {
      expect(() => guards[guard](value)).not.toThrow();
      for (const field of Object.keys(value)) rejects(guard, without(value, field));
      rejects(guard, { ...value, unknown: true });
    }
    for (const value of [
      mutate(fixture.memory, (copy) => Object.assign(copy, { kind: 'unknown' })),
      mutate(fixture.memory, (copy) => Object.assign(copy, { title: ' ' })),
      mutate(fixture.memory, (copy) => Object.assign(copy, { tags: ['tag', 'tag'] })),
      mutate(fixture.memory, (copy) => Object.assign(copy.scope, { unknown: true })),
      mutate(fixture.memory, (copy) => Object.assign(copy.provenance, { unknown: true })),
      mutate(fixture.memory, (copy) => Object.assign(copy.provenance.createdHlc, { logical: -1 })),
      mutate(fixture.memory, (copy) => Object.assign(copy.createdHlc, { physicalMs: '01' })),
    ]) rejects('assertMemoryRecord', value);
    for (const value of [
      mutate(fixture.task, (copy) => Object.assign(copy, { status: 'unknown' })),
      mutate(fixture.task, (copy) => Object.assign(copy, { bodyMarkdown: ' ' })),
      mutate(fixture.task, (copy) => Object.assign(copy, { status: 'done' })),
    ]) rejects('assertTaskRecord', value);
    for (const value of [
      mutate(fixture.setupPlan, (copy) => Object.assign(copy, { harness: 'unknown' })),
      mutate(fixture.setupPlan, (copy) => Object.assign(copy.executablePath, { unknown: true })),
      mutate(fixture.setupPlan, (copy) => Object.assign(copy.executablePath, { bytes: 'Y' })),
      mutate(fixture.setupPlan, (copy) => Object.assign(copy.targetScopes[0], { unknown: true })),
      mutate(fixture.setupPlan, (copy) => Object.assign(copy.permissionDelta, { unknown: true })),
      mutate(fixture.setupPlan, (copy) => Object.assign(copy.networkDelta, { unknown: true })),
      mutate(fixture.setupPlan, (copy) => Object.assign(copy, { expiresAt: '01' })),
    ]) rejects('assertSetupPlan', value);
    for (const value of [
      mutate(fixture.syncOperation, (copy) => Object.assign(copy, { schemaVersion: 2 })),
      mutate(fixture.syncOperation, (copy) => Object.assign(copy, { recordKind: 'unknown' })),
      mutate(fixture.syncOperation, (copy) => Object.assign(copy, { deviceSequence: '01' })),
      mutate(fixture.syncOperation, (copy) => Object.assign(copy.causalFrontier[0], { unknown: true })),
      mutate(fixture.syncOperation, (copy) => Object.assign(copy.blobRefs[0], { ciphertextBytes: '0' })),
      mutate(fixture.syncOperation, (copy) => Object.assign(copy.createdHlc, { unknown: true })),
    ]) rejects('assertSyncOperationV1', value);
  });

  it('rejects unknown local JSON-RPC v1 fields', () => {
    const request = load('crates/protocol/tests/fixtures/runtime-contracts-v1.json').memoryCreateRequest;
    expect(() => guards.assertMemoryCreateJsonRpcRequestV1(request)).not.toThrow();
    rejectsWith(protocolValidation.assertMemoryCreateJsonRpcRequestV1, { ...request, id: 'not-a-uuid' });
    rejectsWith(protocolValidation.assertMemoryCreateJsonRpcRequestV1, { ...request, daemonInstanceNonce: 'AQ' });
    rejectsWith(protocolValidation.assertMemoryCreateJsonRpcRequestV1, { ...request, params: { ...request.params, operationId: 'not-a-uuid' } });
    rejects('assertMemoryCreateJsonRpcRequestV1', { ...request, unknown: true });
    rejects('assertMemoryCreateJsonRpcRequestV1', { ...request, params: { ...request.params, unknown: true } });
  });

  it('validates package and export fixtures', () => {
    const ajv = createProtocolSchemaValidator();
    for (const contract of ['package', 'export']) {
      const validate = ajv.compile(load(`schemas/context-relay-${contract}-v1.json`));
      expect(validate(load(`crates/protocol/tests/fixtures/${contract}-v1-valid.json`))).toBe(true);
      expect(validate(load(`crates/protocol/tests/fixtures/${contract}-v1-invalid.json`))).toBe(false);
    }
    const validateExport = ajv.compile(load('schemas/context-relay-export-v1.json'));
    const exportFixture = load('crates/protocol/tests/fixtures/export-v1-valid.json');
    for (const field of ['harness', 'source']) {
      expect(validateExport(exportFixture), `explicit null ${field}`).toBe(true);
      const omitted = structuredClone(exportFixture);
      delete omitted.records[0].provenance[field];
      expect(validateExport(omitted), `omitted export provenance ${field}`).toBe(false);
    }
  });
});
