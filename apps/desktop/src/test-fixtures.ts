import type { MemoryCandidate, MemoryRecord, ProjectIdentity, TaskRecord } from './bindings';

// Shared protocol-valid record fixtures. The gateway validates every record the
// daemon returns, so tests that exercise it must supply records that satisfy the
// same invariants rather than partial casts.

const NODE = '018f22e2-79b0-7cc8-98c4-dc0c0c075000';

// The final group of a UUIDv7 holds 12 hex digits. Reserve five of them for a
// counter so every generated identifier is still a valid 36-character UUIDv7
// that the protocol validators accept.
const ID_PREFIX = NODE.slice(0, NODE.length - 5);
const ID_DIGITS = 5;

let counter = 0;
/** Deterministic, unique UUIDv7-shaped identifier, branded for any id field. */
export function fixtureId<T extends string = string>() {
  counter += 1;
  return `${ID_PREFIX}${String(counter % 100_000).padStart(ID_DIGITS, '0')}` as T;
}

const hlc = (physicalMs: string) => ({ physicalMs: physicalMs as MemoryRecord['createdHlc']['physicalMs'], logical: 0, node: NODE as MemoryRecord['createdHlc']['node'] });

export function fixtureMemory(overrides: Partial<MemoryRecord> = {}): MemoryRecord {
  return {
    id: fixtureId<MemoryRecord['id']>(),
    scope: { scope: 'global' },
    kind: 'note',
    title: 'Use plain language',
    bodyMarkdown: 'Explain unfamiliar terms.',
    tags: [],
    origin: 'explicit',
    provenance: { originDevice: fixtureId<MemoryRecord['provenance']['originDevice']>(), harness: null, source: null, createdHlc: hlc('1758000000000') },
    revision: fixtureId<MemoryRecord['revision']>(),
    createdHlc: hlc('1758000000000'),
    updatedHlc: hlc('1758000000000'),
    archived: false,
    ...overrides,
  };
}

export function fixtureTask(overrides: Partial<TaskRecord> = {}): TaskRecord {
  return {
    id: fixtureId<TaskRecord['id']>(),
    projectId: fixtureId<TaskRecord['projectId']>(),
    title: 'Fix the sign-in page',
    bodyMarkdown: 'Check the error message.',
    status: 'open',
    evidence: [],
    revision: fixtureId<TaskRecord['revision']>(),
    ...overrides,
  };
}

export function fixtureCandidate(overrides: Partial<MemoryCandidate> = {}): MemoryCandidate {
  return {
    id: fixtureId<MemoryCandidate['id']>(),
    proposedMemory: fixtureMemory(),
    evidenceSummary: 'The user asked to prefer plain language.',
    sourceHarness: 'codex',
    state: 'pending',
    ...overrides,
  };
}

export function fixtureProject(overrides: Partial<ProjectIdentity> = {}): ProjectIdentity {
  return {
    projectId: fixtureId<ProjectIdentity['projectId']>(),
    githubRepositoryId: null,
    gitRemoteFingerprint: null,
    monorepoSubdirectory: null,
    name: 'Website',
    ...overrides,
  };
}
