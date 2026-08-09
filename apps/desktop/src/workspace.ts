import type {
  Base64Url,
  CandidateId,
  LocalRequest,
  LocalResult,
  MemoryCandidate,
  MemoryId,
  MemoryRecord,
  OperationId,
  PairingCode,
  PairingId,
  PairingSafetyNumber,
  ProjectId,
  ProjectIdentity,
  RecoveryEnrollmentConfirmParams,
  RecoveryEnrollmentHostBeginResult,
  RecoveryEnrollmentHostConfirmResult,
  RecoveryEnrollmentId,
  RecoveryEnrollmentStatus,
  Sha256Digest,
  StatusOutput,
  TaskId,
  TaskRecord,
  TaskStatus,
  UuidV7,
} from './bindings';
import { LocalClient } from './local-client';

export type PairingInviteResult = Extract<LocalResult, { kind: 'pairing_invite' }>;
export type PairingRequestResult = Extract<LocalResult, { kind: 'pairing_request' }>;
export type PairingApprovalResult = Extract<LocalResult, { kind: 'pairing_approval' }>;
export type PairingCompletionResult = Extract<LocalResult, { kind: 'pairing_completion' }>;
export type PairingStatusResult = Extract<
  LocalResult,
  | { kind: 'pairing_invite_status' }
  | { kind: 'pairing_request' }
  | { kind: 'pairing_approval' }
  | { kind: 'pairing_completion' }
>;
export type PairingDecisionResult = PairingRequestResult | PairingApprovalResult;

export interface DeviceGateway {
  devices(): Promise<Extract<LocalResult, { kind: 'devices' }>['data']['devices']>;
  createPairingInvite(): Promise<PairingInviteResult>;
  joinPairing(code: PairingCode, deviceName: string): Promise<PairingRequestResult>;
  pairingStatus(pairingId: PairingId): Promise<PairingStatusResult>;
  decidePairing(
    pairingId: PairingId,
    requestDigest: Sha256Digest,
    approve: boolean,
  ): Promise<PairingDecisionResult>;
  confirmPairing(
    pairingId: PairingId,
    safetyNumber: PairingSafetyNumber,
  ): Promise<PairingCompletionResult>;
  cancelPairing(pairingId: PairingId): Promise<void>;
  recoveryEnrollmentBegin(): Promise<RecoveryEnrollmentHostBeginResult>;
  recoveryEnrollmentOverview(): Promise<RecoveryEnrollmentStatus>;
  recoveryEnrollmentConfirm(
    params: RecoveryEnrollmentConfirmParams,
  ): Promise<RecoveryEnrollmentHostConfirmResult>;
  recoveryEnrollmentStatus(enrollmentId: RecoveryEnrollmentId): Promise<RecoveryEnrollmentStatus>;
  recoveryEnrollmentCancel(enrollmentId: RecoveryEnrollmentId): Promise<void>;
}

export interface WorkspaceGateway extends DeviceGateway {
  status(): Promise<StatusOutput>;
  projects(): Promise<ProjectIdentity[]>;
  createProject(name: string, path: string): Promise<ProjectIdentity>;
  memories(projectId: string | null): Promise<MemoryRecord[]>;
  createMemory(
    projectId: string | null,
    title: string,
    bodyMarkdown: string,
  ): Promise<MemoryRecord>;
  updateMemory(
    memory: MemoryRecord,
    title: string,
    bodyMarkdown: string,
  ): Promise<MemoryRecord>;
  archiveMemory(memory: MemoryRecord): Promise<MemoryRecord>;
  searchMemories(query: string, projectId: string | null): Promise<MemoryRecord[]>;
  candidates(projectId: string | null): Promise<MemoryCandidate[]>;
  reviewCandidate(candidate: MemoryCandidate, accepted: boolean): Promise<MemoryCandidate>;
  tasks(projectId: string): Promise<TaskRecord[]>;
  createTask(projectId: string, title: string, bodyMarkdown: string): Promise<TaskRecord>;
  updateTask(task: TaskRecord, title: string, bodyMarkdown: string): Promise<TaskRecord>;
  transitionTask(task: TaskRecord, status: TaskStatus): Promise<TaskRecord>;
  completeTask(task: TaskRecord, summary: string): Promise<TaskRecord>;
}

export class LocalWorkspaceGateway implements WorkspaceGateway {
  constructor(private readonly client = new LocalClient()) {}

  async status() {
    return statusResult(await this.call({ method: 'sync_status', params: {} }));
  }

  async devices() {
    const result = await this.call({ method: 'devices_list', params: {} });
    return result.kind === 'devices' ? result.data.devices : unexpected(result);
  }

  async createPairingInvite(): Promise<PairingInviteResult> {
    const result = await this.call({ method: 'pairing_create', params: {} });
    return result.kind === 'pairing_invite' && result.data.status === 'pending'
      ? result
      : unexpected(result);
  }

  async joinPairing(code: PairingCode, deviceName: string): Promise<PairingRequestResult> {
    const result = await this.call({ method: 'pairing_join', params: { code, deviceName } });
    return result.kind === 'pairing_request' && result.data.status === 'pending'
      ? result
      : unexpected(result);
  }

  async pairingStatus(pairingId: PairingId): Promise<PairingStatusResult> {
    const result = await this.call({ method: 'pairing_status', params: { pairingId } });
    switch (result.kind) {
      case 'pairing_invite_status':
      case 'pairing_request':
      case 'pairing_approval':
      case 'pairing_completion':
        return result;
      default:
        return unexpected(result);
    }
  }

  async decidePairing(
    pairingId: PairingId,
    requestDigest: Sha256Digest,
    approve: boolean,
  ): Promise<PairingDecisionResult> {
    const result = await this.call({
      method: 'pairing_decision',
      params: { pairingId, requestDigest, approve },
    });
    if (approve && result.kind === 'pairing_approval') return result;
    if (!approve && result.kind === 'pairing_request' && result.data.status === 'rejected') {
      return result;
    }
    return unexpected(result);
  }

  async confirmPairing(
    pairingId: PairingId,
    safetyNumber: PairingSafetyNumber,
  ): Promise<PairingCompletionResult> {
    const result = await this.call({
      method: 'pairing_confirm',
      params: { pairingId, safetyNumber },
    });
    return result.kind === 'pairing_completion' ? result : unexpected(result);
  }

  async cancelPairing(pairingId: PairingId) {
    const result = await this.call({ method: 'pairing_cancel', params: { pairingId } });
    if (result.kind !== 'empty') unexpected(result);
  }

  async recoveryEnrollmentBegin() {
    const result = await this.client.recoveryEnrollmentBegin();
    return result.kind === 'challenge' || result.kind === 'status'
      ? result
      : unexpectedNativeResult(result);
  }

  async recoveryEnrollmentOverview() {
    return recoveryStatusResult(
      await this.call({ method: 'recovery_enrollment_overview', params: {} }),
    );
  }

  async recoveryEnrollmentConfirm(params: RecoveryEnrollmentConfirmParams) {
    const result = await this.client.recoveryEnrollmentConfirm(params);
    switch (result.kind) {
      case 'canceled':
      case 'complete':
      case 'status':
        return result;
      default:
        return unexpectedNativeResult(result);
    }
  }

  async recoveryEnrollmentStatus(enrollmentId: RecoveryEnrollmentId) {
    return recoveryStatusResult(
      await this.call({ method: 'recovery_enrollment_status', params: { enrollmentId } }),
    );
  }

  async recoveryEnrollmentCancel(enrollmentId: RecoveryEnrollmentId) {
    const status = recoveryStatusResult(
      await this.call({
        method: 'recovery_enrollment_cancel',
        params: { enrollmentId },
      }),
    );
    if (status.state !== 'idle' || status.enrollmentId !== null) {
      throw new Error('Recovery cancellation did not return an idle status.');
    }
  }

  async projects() {
    const result = await this.call({ method: 'projects_list', params: {} });
    return result.kind === 'projects' ? result.data.projects : unexpected(result);
  }

  async createProject(name: string, path: string) {
    const project: ProjectIdentity = {
      projectId: uuidV7() as ProjectId,
      githubRepositoryId: null,
      gitRemoteFingerprint: null,
      monorepoSubdirectory: null,
      name,
    };
    await this.call({ method: 'project_upsert', params: { project } });
    await this.call({
      method: 'project_path_set',
      params: { projectId: project.projectId, path: nativePath(path) },
    });
    return project;
  }

  async memories(projectId: string | null) {
    const result = await this.call({
      method: 'memory_list',
      params: {
        projectId: projectId as ProjectId | null,
        includeArchived: false,
      },
    });
    return result.kind === 'memories' ? result.data.memories : unexpected(result);
  }

  async createMemory(projectId: string | null, title: string, bodyMarkdown: string) {
    return memoryResult(
      await this.call({
        method: 'memory_create',
        params: {
          operationId: uuidV7() as OperationId,
          scope: projectId
            ? { scope: 'project', projectId: projectId as ProjectId }
            : { scope: 'global' },
          kind: 'note',
          title,
          bodyMarkdown,
          tags: [],
        },
      }),
    );
  }

  async updateMemory(memory: MemoryRecord, title: string, bodyMarkdown: string) {
    return memoryResult(
      await this.call({
        method: 'memory_update',
        params: {
          operationId: uuidV7() as OperationId,
          memoryId: memory.id as MemoryId,
          expectedRevision: memory.revision,
          title,
          bodyMarkdown,
          tags: null,
        },
      }),
    );
  }

  async archiveMemory(memory: MemoryRecord) {
    return memoryResult(
      await this.call({
        method: 'memory_archive',
        params: {
          operationId: uuidV7() as OperationId,
          memoryId: memory.id as MemoryId,
          expectedRevision: memory.revision,
        },
      }),
    );
  }

  async searchMemories(query: string, projectId: string | null) {
    const result = await this.call({
      method: 'memory_search',
      params: { query, projectId: projectId as ProjectId | null },
    });
    return result.kind === 'memories' ? result.data.memories : unexpected(result);
  }

  async candidates(projectId: string | null) {
    const result = await this.call({
      method: 'candidates_list',
      params: { projectId: projectId as ProjectId | null },
    });
    return result.kind === 'candidates' ? result.data.candidates : unexpected(result);
  }

  async reviewCandidate(candidate: MemoryCandidate, accepted: boolean) {
    const result = await this.call({
      method: 'candidate_review',
      params: {
        candidateId: candidate.id as CandidateId,
        accepted,
        operationId: uuidV7() as OperationId,
      },
    });
    return result.kind === 'candidates' && result.data.candidates[0]
      ? result.data.candidates[0]
      : unexpected(result);
  }

  async tasks(projectId: string) {
    const result = await this.call({
      method: 'tasks_list',
      params: { projectId: projectId as ProjectId },
    });
    return result.kind === 'tasks' ? result.data.tasks : unexpected(result);
  }

  async createTask(projectId: string, title: string, bodyMarkdown: string) {
    return taskResult(
      await this.call({
        method: 'task_upsert',
        params: {
          operationId: uuidV7() as OperationId,
          taskId: null,
          projectId: projectId as ProjectId,
          title,
          bodyMarkdown,
          status: 'open',
          expectedRevision: null,
        },
      }),
    );
  }

  async updateTask(task: TaskRecord, title: string, bodyMarkdown: string) {
    return taskResult(
      await this.call({
        method: 'task_upsert',
        params: {
          operationId: uuidV7() as OperationId,
          taskId: task.id as TaskId,
          projectId: task.projectId,
          title,
          bodyMarkdown,
          status: task.status,
          expectedRevision: task.revision,
        },
      }),
    );
  }

  async transitionTask(task: TaskRecord, status: TaskStatus) {
    return taskResult(
      await this.call({
        method: 'task_transition',
        params: {
          operationId: uuidV7() as OperationId,
          taskId: task.id as TaskId,
          expectedRevision: task.revision,
          status,
        },
      }),
    );
  }

  async completeTask(task: TaskRecord, summary: string) {
    return taskResult(
      await this.call({
        method: 'task_complete',
        params: {
          operationId: uuidV7() as OperationId,
          taskId: task.id as TaskId,
          expectedRevision: task.revision,
          evidence: [{ summary, kind: 'manual', reference: null }],
        },
      }),
    );
  }

  private call(request: LocalRequest) {
    return this.client.call(request);
  }
}

function statusResult(result: LocalResult) {
  return result.kind === 'status' ? result.data.status : unexpected(result);
}

function recoveryStatusResult(result: LocalResult) {
  return result.kind === 'recovery_enrollment_status'
    ? result.data.status
    : unexpected(result);
}

function memoryResult(result: LocalResult) {
  return result.kind === 'memory' && result.data.memory ? result.data.memory : unexpected(result);
}

function taskResult(result: LocalResult) {
  return result.kind === 'tasks' && result.data.tasks[0] ? result.data.tasks[0] : unexpected(result);
}

function unexpected(result: LocalResult): never {
  throw new Error(`Unexpected local result: ${result.kind}`);
}

function unexpectedNativeResult(result: never): never {
  throw new Error(`Unexpected native recovery result: ${String(result)}`);
}

function uuidV7(): UuidV7 {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let timestamp = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}` as UuidV7;
}

function nativePath(path: string) {
  const macos = navigator.userAgent.includes('Mac');
  const bytes = macos
    ? new TextEncoder().encode(path)
    : Uint8Array.from(
        [...path].flatMap((character) => {
          const code = character.charCodeAt(0);
          return [code & 0xff, code >> 8];
        }),
      );
  const binary = [...bytes].map((byte) => String.fromCharCode(byte)).join('');
  return {
    platform: macos ? ('macos' as const) : ('windows' as const),
    bytes: btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '') as Base64Url,
    display: path,
  };
}
