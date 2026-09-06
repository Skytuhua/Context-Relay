import Ajv2020 from 'ajv/dist/2020.js';

import type { HarnessPreparationStatus, HarnessExecutionStatus, HarnessSetupRecord, HarnessSetupsPage, MemoryRecord, ProbeReport, SetupPlan, SyncOperationV1, TaskRecord } from './bindings';

const utf8 = new TextEncoder();
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const digest = /^[0-9a-f]{64}$/;
const decimal = /^(?:0|[1-9][0-9]*)$/;
const base64url = /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$/;
const unsafeNativeDisplay = (value: string) =>
  Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) as number;
    return (
      codePoint <= 0x1f ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      codePoint === 0x061c ||
      codePoint === 0x200e ||
      codePoint === 0x200f ||
      (codePoint >= 0x202a && codePoint <= 0x202e) ||
      (codePoint >= 0x2066 && codePoint <= 0x2069)
    );
  });
const u64Max = 18_446_744_073_709_551_615n;
const adapterCollectionLimit = 1024;
const adapterTextLimit = 16 * 1024;

const fail = (field: string): never => { throw new TypeError(`invalid ${field}`); };
const object = (value: unknown, keys: readonly string[], field: string) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(field);
  const result = value as Record<string, unknown>;
  const actual = Object.keys(result);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) fail(field);
  return result;
};
const string = (value: unknown, field: string) => typeof value === 'string' ? value : fail(field);
const text = (value: unknown, limit: number, field: string) => {
  const result = string(value, field);
  if (!result.trim() || utf8.encode(result).byteLength > limit) fail(field);
  return result;
};
const optionalText = (value: unknown, limit: number, field: string) => {
  if (value !== null && (typeof value !== 'string' || utf8.encode(value).byteLength > limit)) fail(field);
};
const choice = (value: unknown, choices: readonly unknown[], field: string) => {
  if (!choices.includes(value)) fail(field);
};
const uint = (value: unknown, max: number, field: string) => {
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > max) fail(field);
};
const list = (value: unknown, limit: number, field: string): unknown[] => {
  if (!Array.isArray(value) || value.length > limit) fail(field);
  return value as unknown[];
};
const id = (value: unknown, field: string) => {
  if (typeof value !== 'string' || !uuid.test(value)) fail(field);
};
const u64 = (value: unknown, field: string) => {
  if (typeof value !== 'string' || value.length > 20 || !decimal.test(value) || BigInt(value) > u64Max) fail(field);
};
const sha = (value: unknown, field: string) => {
  if (typeof value !== 'string' || !digest.test(value)) fail(field);
};
const bytes = (value: unknown, field: string) => {
  const encoded = string(value, field);
  if (!base64url.test(encoded)) fail(field);
  return Math.floor(encoded.length * 3 / 4);
};
const fixed = (value: unknown, size: number, field: string) => {
  if (bytes(value, field) !== size) fail(field);
};
const hlc = (value: unknown, field: string) => {
  const item = object(value, ['physicalMs', 'logical', 'node'], field);
  u64(item.physicalMs, `${field}.physicalMs`); uint(item.logical, 0xffff_ffff, `${field}.logical`); id(item.node, `${field}.node`);
};
const scope = (value: unknown, field: string) => {
  const project = value && (value as Record<string, unknown>).scope === 'project';
  const item = object(value, project ? ['scope', 'projectId'] : ['scope'], field);
  choice(item.scope, ['global', 'project'], `${field}.scope`);
  if (project) id(item.projectId, `${field}.projectId`);
};
const provenance = (value: unknown, field: string) => {
  const item = object(value, ['originDevice', 'harness', 'source', 'createdHlc'], field);
  id(item.originDevice, `${field}.originDevice`);
  if (item.harness !== null) choice(item.harness, ['claude_code', 'codex', 'hermes'], `${field}.harness`);
  if (item.source !== null) {
    const tagged = item.source as Record<string, unknown>;
    const key = tagged.source === 'record' ? 'recordId' : 'packageId';
    const source = object(tagged, ['source', key], `${field}.source`);
    choice(source.source, ['record', 'package'], `${field}.source.source`); id(source[key], `${field}.source.${key}`);
  }
  hlc(item.createdHlc, `${field}.createdHlc`);
};

export const assertMemoryRecord = (value: unknown): asserts value is MemoryRecord => {
  const item = object(value, ['id', 'scope', 'kind', 'title', 'bodyMarkdown', 'tags', 'origin', 'provenance', 'revision', 'createdHlc', 'updatedHlc', 'archived'], 'memory');
  id(item.id, 'memory.id'); scope(item.scope, 'memory.scope');
  choice(item.kind, ['fact', 'decision', 'preference', 'pattern', 'procedure', 'note'], 'memory.kind');
  text(item.title, 512, 'memory.title'); text(item.bodyMarkdown, 1024 * 1024, 'memory.bodyMarkdown');
  const seen = new Set<string>();
  for (const value of list(item.tags, 64, 'memory.tags')) { const tag = text(value, 128, 'memory.tags'); if (seen.has(tag)) fail('memory.tags'); seen.add(tag); }
  choice(item.origin, ['explicit', 'inferred', 'native_import', 'package_import'], 'memory.origin');
  provenance(item.provenance, 'memory.provenance'); id(item.revision, 'memory.revision');
  hlc(item.createdHlc, 'memory.createdHlc'); hlc(item.updatedHlc, 'memory.updatedHlc');
  if (typeof item.archived !== 'boolean') fail('memory.archived');
};

export const assertTaskRecord = (value: unknown): asserts value is TaskRecord => {
  const item = object(value, ['id', 'projectId', 'title', 'bodyMarkdown', 'status', 'evidence', 'revision'], 'task');
  id(item.id, 'task.id'); id(item.projectId, 'task.projectId'); text(item.title, 512, 'task.title'); text(item.bodyMarkdown, 1024 * 1024, 'task.bodyMarkdown');
  choice(item.status, ['open', 'in_progress', 'blocked', 'done', 'canceled'], 'task.status');
  const evidence = list(item.evidence, 64, 'task.evidence');
  if (item.status === 'done' && evidence.length === 0) fail('task.evidence');
  for (const value of evidence) {
    const nested = object(value, ['summary', 'evidenceKind', 'reference', 'recordedHlc'], 'task.evidence');
    text(nested.summary, 16 * 1024, 'task.evidence.summary'); text(nested.evidenceKind, 128, 'task.evidence.evidenceKind');
    optionalText(nested.reference, 16 * 1024, 'task.evidence.reference'); hlc(nested.recordedHlc, 'task.evidence.recordedHlc');
  }
  id(item.revision, 'task.revision');
};

const native = (value: unknown, field: string) => {
  const hasDisplay = typeof value === 'object'
    && value !== null
    && Object.prototype.hasOwnProperty.call(value, 'display');
  const item = object(value, hasDisplay ? ['platform', 'bytes', 'display'] : ['platform', 'bytes'], field);
  choice(item.platform, ['windows', 'macos'], `${field}.platform`);
  const length = bytes(item.bytes, `${field}.bytes`);
  if (length > 1024 * 1024 || (item.platform === 'windows' && length % 2)) fail(`${field}.bytes`);
  if (hasDisplay) {
    optionalText(item.display, 1024, `${field}.display`);
    if (typeof item.display === 'string' && unsafeNativeDisplay(item.display)) fail(`${field}.display`);
  }
};
const nativeScope = (value: unknown, field: string) => {
  const project = value && (value as Record<string, unknown>).scope === 'project';
  const item = object(value, project ? ['scope', 'projectId', 'root'] : ['scope'], field);
  choice(item.scope, ['global', 'project'], `${field}.scope`);
  if (project) { id(item.projectId, `${field}.projectId`); native(item.root, `${field}.root`); }
};

export const assertProbeReport = (value: unknown): asserts value is ProbeReport => {
  const item = object(value, ['executable', 'executableSha256', 'harnessVersion', 'installationMethod', 'configRoots', 'activeProfile', 'policyConflicts', 'capability', 'codexSavedHookApproval'], 'probeReport');
  if (item.codexSavedHookApproval !== null) {
    const approval = object(item.codexSavedHookApproval, ['sessionStart', 'stop'], 'probeReport.codexSavedHookApproval');
    for (const key of ['sessionStart', 'stop']) choice(approval[key], ['missing', 'needs_approval', 'approved', 'changed', 'disabled'], 'probeReport.codexSavedHookApproval');
  }
  if (item.executable !== null) native(item.executable, 'probeReport.executable');
  if (item.executableSha256 !== null) sha(item.executableSha256, 'probeReport.executableSha256');
  if (item.harnessVersion !== null) text(item.harnessVersion, adapterTextLimit, 'probeReport.harnessVersion');
  if (item.activeProfile !== null) text(item.activeProfile, adapterTextLimit, 'probeReport.activeProfile');
  choice(item.installationMethod, ['bundled', 'package_manager', 'manual', 'unknown'], 'probeReport.installationMethod');
  choice(item.capability, ['full', 'import_only', 'blocked', 'missing'], 'probeReport.capability');
  for (const value of list(item.configRoots, adapterCollectionLimit, 'probeReport.configRoots')) native(value, 'probeReport.configRoots');
  for (const value of list(item.policyConflicts, adapterCollectionLimit, 'probeReport.policyConflicts')) text(value, adapterTextLimit, 'probeReport.policyConflicts');
};

const dependency = (value: unknown, field: string) => {
  const item = object(value, ['name', 'version', 'digest', 'immutableSourceRef'], field);
  text(item.name, 512, `${field}.name`); text(item.version, 512, `${field}.version`); sha(item.digest, `${field}.digest`); text(item.immutableSourceRef, 1024 * 1024, `${field}.immutableSourceRef`);
};
const endpoint = (value: unknown, field: string) => {
  const item = object(value, ['scheme', 'host', 'port'], field); choice(item.scheme, ['https', 'wss'], `${field}.scheme`);
  const host = string(item.host, `${field}.host`);
  if (!/^(?=.{1,253}$)(?!\.)(?!.*\.$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$/.test(host)) fail(`${field}.host`);
  uint(item.port, 0xffff, `${field}.port`); if (item.port === 0) fail(`${field}.port`);
};

export const assertSetupPlan = (value: unknown): asserts value is SetupPlan => {
  const item = object(value, ['planId', 'harness', 'harnessProfile', 'adapterVersion', 'executablePath', 'executableHash', 'harnessVersion', 'targetScopes', 'expectedNativeDigests', 'semanticChanges', 'cliOperations', 'packageArtifacts', 'permissionDelta', 'networkDelta', 'scannerReportHash', 'rulesyncVersion', 'rulesyncHash', 'approvalClass', 'expiresAt', 'batchHash'], 'setupPlan');
  id(item.planId, 'setupPlan.planId'); choice(item.harness, ['claude_code', 'codex', 'hermes'], 'setupPlan.harness'); uint(item.adapterVersion, 0xffff_ffff, 'setupPlan.adapterVersion');
  if (item.harness === 'hermes') text(item.harnessProfile, 512, 'setupPlan.harnessProfile');
  else if (item.harnessProfile !== null) fail('setupPlan.harnessProfile');
  native(item.executablePath, 'setupPlan.executablePath'); sha(item.executableHash, 'setupPlan.executableHash'); text(item.harnessVersion, 512, 'setupPlan.harnessVersion');
  for (const value of list(item.targetScopes, adapterCollectionLimit, 'setupPlan.targetScopes')) nativeScope(value, 'setupPlan.targetScopes');
  for (const value of list(item.expectedNativeDigests, adapterCollectionLimit, 'setupPlan.expectedNativeDigests')) { const nested = object(value, ['target', 'expectedDigest'], 'setupPlan.expectedNativeDigests'); native(nested.target, 'setupPlan.expectedNativeDigests.target'); if (nested.expectedDigest !== null) sha(nested.expectedDigest, 'setupPlan.expectedNativeDigests.expectedDigest'); }
  for (const value of list(item.semanticChanges, adapterCollectionLimit, 'setupPlan.semanticChanges')) { const nested = object(value, ['class', 'target', 'summary'], 'setupPlan.semanticChanges'); choice(nested.class, ['create', 'update', 'remove', 'enable', 'disable', 'preserve', 'conflict'], 'setupPlan.semanticChanges.class'); text(nested.target, adapterTextLimit, 'setupPlan.semanticChanges.target'); text(nested.summary, adapterTextLimit, 'setupPlan.semanticChanges.summary'); }
  for (const value of list(item.cliOperations, adapterCollectionLimit, 'setupPlan.cliOperations')) { const nested = object(value, ['executable', 'arguments', 'timeoutMs'], 'setupPlan.cliOperations'); native(nested.executable, 'setupPlan.cliOperations.executable'); for (const argument of list(nested.arguments, adapterCollectionLimit, 'setupPlan.cliOperations.arguments')) native(argument, 'setupPlan.cliOperations.arguments'); uint(nested.timeoutMs, 0xffff_ffff, 'setupPlan.cliOperations.timeoutMs'); }
  for (const value of list(item.packageArtifacts, adapterCollectionLimit, 'setupPlan.packageArtifacts')) {
    const nested = object(value, ['packageId', 'immutableSourceRef', 'resolvedCommit', 'archiveDigest', 'artifactPath', 'artifactDigest', 'dependencies'], 'setupPlan.packageArtifacts');
    id(nested.packageId, 'setupPlan.packageArtifacts.packageId'); text(nested.immutableSourceRef, adapterTextLimit, 'setupPlan.packageArtifacts.immutableSourceRef');
    if (typeof nested.resolvedCommit !== 'string' || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(nested.resolvedCommit)) fail('setupPlan.packageArtifacts.resolvedCommit');
    sha(nested.archiveDigest, 'setupPlan.packageArtifacts.archiveDigest'); native(nested.artifactPath, 'setupPlan.packageArtifacts.artifactPath'); sha(nested.artifactDigest, 'setupPlan.packageArtifacts.artifactDigest');
    for (const child of list(nested.dependencies, adapterCollectionLimit, 'setupPlan.packageArtifacts.dependencies')) dependency(child, 'setupPlan.packageArtifacts.dependencies');
  }
  for (const name of ['permissionDelta', 'networkDelta'] as const) { const delta = object(item[name], ['added', 'removed'], `setupPlan.${name}`); for (const side of ['added', 'removed'] as const) for (const value of list(delta[side], adapterCollectionLimit, `setupPlan.${name}.${side}`)) { if (name === 'permissionDelta') text(value, 512, `setupPlan.${name}.${side}`); else endpoint(value, `setupPlan.${name}.${side}`); } }
  sha(item.scannerReportHash, 'setupPlan.scannerReportHash'); text(item.rulesyncVersion, 512, 'setupPlan.rulesyncVersion'); sha(item.rulesyncHash, 'setupPlan.rulesyncHash'); choice(item.approvalClass, ['passive', 'active'], 'setupPlan.approvalClass'); u64(item.expiresAt, 'setupPlan.expiresAt'); sha(item.batchHash, 'setupPlan.batchHash');
};

export const assertSyncOperationV1 = (value: unknown): asserts value is SyncOperationV1 => {
  const item = object(value, ['schemaVersion', 'operationId', 'accountId', 'workspaceId', 'projectId', 'recordId', 'recordKind', 'mutationKind', 'deviceId', 'deviceSequence', 'causalFrontier', 'controlEpoch', 'keyEpoch', 'previousDeviceHash', 'nonce', 'ciphertext', 'ciphertextHash', 'blobRefs', 'createdHlc', 'signature'], 'syncOperation');
  if (item.schemaVersion !== 1) fail('syncOperation.schemaVersion');
  for (const name of ['operationId', 'accountId', 'workspaceId', 'recordId', 'deviceId'] as const) id(item[name], `syncOperation.${name}`);
  if (item.projectId !== null) id(item.projectId, 'syncOperation.projectId');
  choice(item.recordKind, ['memory', 'memory_candidate', 'task', 'secret_ref', 'instruction', 'component', 'project'], 'syncOperation.recordKind'); choice(item.mutationKind, ['upsert', 'tombstone'], 'syncOperation.mutationKind'); u64(item.deviceSequence, 'syncOperation.deviceSequence');
  let prior = '';
  for (const value of list(item.causalFrontier, 10_000, 'syncOperation.causalFrontier')) { const nested = object(value, ['deviceId', 'sequence'], 'syncOperation.causalFrontier'); id(nested.deviceId, 'syncOperation.causalFrontier.deviceId'); if ((nested.deviceId as string) <= prior) fail('syncOperation.causalFrontier'); prior = nested.deviceId as string; u64(nested.sequence, 'syncOperation.causalFrontier.sequence'); }
  uint(item.controlEpoch, 0xffff_ffff, 'syncOperation.controlEpoch'); uint(item.keyEpoch, 0xffff_ffff, 'syncOperation.keyEpoch'); sha(item.previousDeviceHash, 'syncOperation.previousDeviceHash'); fixed(item.nonce, 24, 'syncOperation.nonce');
  if (bytes(item.ciphertext, 'syncOperation.ciphertext') > 4 * 1024 * 1024) fail('syncOperation.ciphertext'); sha(item.ciphertextHash, 'syncOperation.ciphertextHash');
  for (const value of list(item.blobRefs, 10_000, 'syncOperation.blobRefs')) { const nested = object(value, ['digest', 'ciphertextBytes', 'storageId'], 'syncOperation.blobRefs'); sha(nested.digest, 'syncOperation.blobRefs.digest'); u64(nested.ciphertextBytes, 'syncOperation.blobRefs.ciphertextBytes'); if (nested.ciphertextBytes === '0' || BigInt(nested.ciphertextBytes as string) > 500n * 1024n * 1024n) fail('syncOperation.blobRefs.ciphertextBytes'); text(nested.storageId, 512, 'syncOperation.blobRefs.storageId'); }
  hlc(item.createdHlc, 'syncOperation.createdHlc'); fixed(item.signature, 64, 'syncOperation.signature');
};

export const assertMemoryCreateJsonRpcRequestV1 = (value: unknown) => {
  const item = object(value, ['jsonrpc', 'id', 'protocol', 'daemonInstanceNonce', 'method', 'params'], 'jsonRpc');
  if (item.jsonrpc !== '2.0' || item.method !== 'memory_create') fail('jsonRpc'); id(item.id, 'jsonRpc.id');
  const protocol = object(item.protocol, ['major', 'minor'], 'jsonRpc.protocol'); uint(protocol.major, 0xffff, 'jsonRpc.protocol.major'); uint(protocol.minor, 0xffff, 'jsonRpc.protocol.minor'); if (protocol.major !== 1) fail('jsonRpc.protocol.major');
  fixed(item.daemonInstanceNonce, 32, 'jsonRpc.daemonInstanceNonce');
  const params = object(item.params, ['operationId', 'scope', 'kind', 'title', 'bodyMarkdown', 'tags'], 'jsonRpc.params');
  id(params.operationId, 'jsonRpc.params.operationId'); scope(params.scope, 'jsonRpc.params.scope'); choice(params.kind, ['fact', 'decision', 'preference', 'pattern', 'procedure', 'note'], 'jsonRpc.params.kind'); text(params.title, 512, 'jsonRpc.params.title'); text(params.bodyMarkdown, 1024 * 1024, 'jsonRpc.params.bodyMarkdown');
  const seen = new Set<string>(); for (const value of list(params.tags, 64, 'jsonRpc.params.tags')) { const tag = text(value, 128, 'jsonRpc.params.tags'); if (seen.has(tag)) fail('jsonRpc.params.tags'); seen.add(tag); }
};

export const createProtocolSchemaValidator = () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  ajv.addKeyword({ keyword: 'x-utf8-maxBytes', schemaType: 'number', type: 'string', validate: (limit: number, value: string) => utf8.encode(value).byteLength <= limit });
  return ajv;
};
export const assertSha256Hex = (value: string) => sha(value, 'SHA-256 hex');
export const assertBase64UrlBytes = (value: string, size: number) => fixed(value, size, 'fixed-size base64url');

const setupStates = ['previewed', 'applying', 'applied', 'apply_restored', 'rolling_back', 'rolled_back', 'rollback_restored', 'conflict', 'expired'];
function clientError(value: unknown, field: string) {
  const error = object(value, ['code', 'message', 'fieldPath', 'retryable'], field);
  choice(error.code, ['protocol_version_unsupported', 'invalid_request', 'frame_too_large', 'vault_locked', 'not_found', 'revision_conflict', 'scope_denied', 'approval_required', 'plan_changed', 'plan_expired', 'harness_unsupported', 'conflict', 'quota_exceeded', 'canceled', 'timeout', 'busy', 'internal'], `${field}.code`);
  text(error.message, 512, `${field}.message`);
  if (error.fieldPath !== null) string(error.fieldPath, `${field}.fieldPath`);
  choice(error.retryable, [true, false], `${field}.retryable`);
}

export function validateHarnessPreparation(value: unknown): HarnessPreparationStatus {
  const item = object(value, ['operationId', 'selection', 'phase', 'completedFiles', 'completedBytes', 'error'], 'harnessPreparation');
  id(item.operationId, 'harnessPreparation.operationId');
  const selection = object(item.selection, ['harness', 'projectId', 'hermesProfile'], 'harnessPreparation.selection');
  if (selection.harness !== 'hermes') fail('harnessPreparation.harness');
  if (selection.projectId !== null) id(selection.projectId, 'harnessPreparation.projectId');
  const profile = text(selection.hermesProfile, 64, 'harnessPreparation.profile');
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(profile)) fail('harnessPreparation.profile');
  choice(item.phase, ['inspecting', 'copying', 'checking_source', 'checking_copy', 'retaining', 'cancelling', 'ready', 'canceled', 'failed'], 'harnessPreparation.phase');
  uint(item.completedFiles, 32768, 'harnessPreparation.completedFiles');
  uint(item.completedBytes, 1_073_741_824, 'harnessPreparation.completedBytes');
  if ((item.phase === 'failed') !== (item.error !== null)) fail('harnessPreparation.error');
  if (item.error !== null) clientError(item.error, 'harnessPreparation.error');
  return value as HarnessPreparationStatus;
}

export function validateHarnessExecution(value: unknown): HarnessExecutionStatus {
  const item = object(value, ['planId', 'action', 'phase', 'error'], 'harnessExecution');
  id(item.planId, 'harnessExecution.planId');
  choice(item.action, ['apply', 'rollback'], 'harnessExecution.action');
  choice(item.phase, ['queued', 'running', 'finished', 'unknown'], 'harnessExecution.phase');
  if (item.error !== null) {
    if (item.phase !== 'finished') fail('harnessExecution.error');
    clientError(item.error, 'harnessExecution.error');
  }
  return value as HarnessExecutionStatus;
}

export function validateHarnessSetupRecord(value: unknown): HarnessSetupRecord {
  const item = object(value, ['plan', 'state', 'createdAt'], 'harnessSetup');
  const assertPlan: (value: unknown) => asserts value is SetupPlan = assertSetupPlan;
  assertPlan(item.plan);
  if (item.plan.rulesyncVersion !== 'bridge-preview-v1') fail('harnessSetup.plan');
  choice(item.state, setupStates, 'harnessSetup.state');
  u64(item.createdAt, 'harnessSetup.createdAt');
  return value as HarnessSetupRecord;
}

export function validateHarnessSetupsPage(value: unknown): HarnessSetupsPage {
  const page = object(value, ['setups', 'nextAfter'], 'harnessSetups');
  let previous: string | null = null;
  for (const value of list(page.setups, 50, 'harnessSetups.setups')) {
    const item = object(value, ['planId', 'harness', 'harnessProfile', 'targetScopes', 'state', 'createdAt', 'expiresAt'], 'harnessSetups.setup');
    id(item.planId, 'harnessSetups.planId');
    if (previous !== null && (item.planId as string) >= previous) fail('harnessSetups.order');
    previous = item.planId as string;
    choice(item.harness, ['codex', 'claude_code', 'hermes'], 'harnessSetups.harness');
    if (item.harness === 'hermes') text(item.harnessProfile, 512, 'harnessSetups.profile');
    else if (item.harnessProfile !== null) fail('harnessSetups.profile');
    const scopes = list(item.targetScopes, adapterCollectionLimit, 'harnessSetups.scopes');
    if (!scopes.length) fail('harnessSetups.scopes');
    scopes.forEach(value => scope(value, 'harnessSetups.scope'));
    choice(item.state, setupStates, 'harnessSetups.state');
    u64(item.createdAt, 'harnessSetups.createdAt'); u64(item.expiresAt, 'harnessSetups.expiresAt');
  }
  if (page.nextAfter !== null) {
    id(page.nextAfter, 'harnessSetups.nextAfter');
    if (previous !== null && (page.nextAfter as string) > previous) fail('harnessSetups.nextAfter');
  }
  return value as HarnessSetupsPage;
}
