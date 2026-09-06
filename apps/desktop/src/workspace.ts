import type {
  Base64Url,
  CandidateId,
  DesktopWrite,
  DesktopWritesPage,
  HarnessParams,
  HarnessPrepareParams,
  HarnessExecutionParams,
  LocalRequest,
  LocalResult,
  MemoryCandidate,
  MemoryId,
  MemoryRecord,
  OperationId,
  PairingCode,
  PairingId,
  PairingSafetyNumber,
  PlanId,
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
} from './bindings';
import { LocalClient } from './local-client';
import { uuidV7 } from './uuid';
import { type HarnessGateway, requireHarnessAcknowledgment, validateHarnessPlan, validateHarnessProbe } from './harness-gateway';
import { validateHarnessPreparation, validateHarnessExecution, validateHarnessSetupRecord, validateHarnessSetupsPage } from './protocol-validation';

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

function harnessResult(result: unknown, kind: string, field: string): unknown {
  if (!result || typeof result !== 'object' || Object.keys(result).length !== 2 ||
    !('kind' in result) || result.kind !== kind || !('data' in result) ||
    !result.data || typeof result.data !== 'object' || Array.isArray(result.data) ||
    Object.keys(result.data).length !== 1 || !(field in result.data)) {
    throw new Error('The harness response was not confirmed.');
  }
  return (result.data as Record<string, unknown>)[field];
}

export class RecoveryStorageFullError extends Error {
  constructor() {
    super('Recovery storage is full. Your draft is still here. Review or dismiss older recovery copies below, then try saving again.');
  }
}

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

export interface WorkspaceGateway extends DeviceGateway, HarnessGateway {
  pendingWrites(after: OperationId | null): Promise<DesktopWritesPage>;
  pendingWrite(operationId: OperationId): Promise<DesktopWrite | null>;
  retryWrite(write: DesktopWrite): Promise<{ cleanupPending: boolean }>;
  forgetWrite(operationId: OperationId): Promise<void>;
  chooseProjectFolder(): Promise<string | null>;
  status(): Promise<StatusOutput>;
  projects(): Promise<ProjectIdentity[]>;
  createProject(name: string, path: string): Promise<ProjectIdentity>;
  memories(projectId: string | null): Promise<MemoryRecord[]>;
  createMemory(
    projectId: string | null,
    title: string,
    bodyMarkdown: string,
    attempt?: object,
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
  createTask(projectId: string, title: string, bodyMarkdown: string, attempt?: object): Promise<TaskRecord>;
  updateTask(task: TaskRecord, title: string, bodyMarkdown: string): Promise<TaskRecord>;
  transitionTask(task: TaskRecord, status: TaskStatus): Promise<TaskRecord>;
  completeTask(task: TaskRecord, summary: string): Promise<TaskRecord>;
}

export class LocalWorkspaceGateway implements WorkspaceGateway {
  private pendingProject: { name: string; pathKey: string; project: ProjectIdentity } | null = null;
  private readonly pendingOperations = new Map<string, { operationId: OperationId; createsRecord: boolean }>();
  private readonly draftAttempts = new WeakMap<object, number>();
  private nextDraftAttempt = 1;
  constructor(private readonly client = new LocalClient()) {}

  async pendingWrites(after: OperationId | null): Promise<DesktopWritesPage> {
    const result = await this.client.call({ method: 'desktop_writes_list', params: { after } });
    if (result.kind !== 'desktop_writes') return unexpected(result);
    const page = result.data.page;
    if (!page || !Array.isArray(page.writes) || page.writes.length > 50 ||
      !(page.nextCursor === null || typeof page.nextCursor === 'string') ||
      page.writes.some((write, index) => !write || typeof write.operationId !== 'string' ||
        typeof write.action !== 'string' || typeof write.title !== 'string' ||
        write.operationId <= (index ? page.writes[index - 1].operationId : after ?? '')) ||
      (page.nextCursor !== null && page.nextCursor !== page.writes.at(-1)?.operationId)) {
      throw new Error('Unconfirmed changes could not be read.');
    }
    return page;
  }

  async pendingWrite(operationId: OperationId): Promise<DesktopWrite | null> {
    const result = await this.client.call({ method: 'desktop_write_get', params: { operationId } });
    if (result.kind !== 'desktop_write') return unexpected(result);
    const write = result.data.write;
    if (write === null) return null;
    if (!write || !['memory_create', 'memory_update', 'memory_archive', 'task_upsert',
      'task_complete', 'task_transition', 'candidate_review'].includes(write.method) ||
      write.params?.operationId !== operationId) throw new Error('The recovery copy could not be read.');
    return write;
  }

  async retryWrite(write: DesktopWrite): Promise<{ cleanupPending: boolean }> {
    // Re-read the immutable copy so a stale review cannot become a different write.
    const stored = await this.pendingWrite(write.params.operationId);
    if (!stored || JSON.stringify(stored) !== JSON.stringify(write)) {
      throw new Error('This recovery copy changed. Reload the list before retrying.');
    }
    const result = await this.client.call(stored);
    const record = writeRecord(stored, result);
    this.retirePending(stored.params.operationId, record.id);
    return { cleanupPending: !(await this.cleanupWrite(stored.params.operationId)) };
  }

  async forgetWrite(operationId: OperationId): Promise<void> {
    const result = await this.client.call({ method: 'desktop_write_forget', params: { operationId } });
    if (result.kind !== 'empty') unexpected(result);
    this.retirePending(operationId);
  }

  private retirePending(operationId: OperationId, recordId?: string) {
    for (const [key, pending] of this.pendingOperations) {
      if (pending.operationId === operationId || (pending.createsRecord && pending.operationId === recordId)) {
        this.pendingOperations.delete(key);
      }
    }
  }

  private async cleanupWrite(operationId: OperationId): Promise<boolean> {
    try {
      await this.forgetWrite(operationId);
      return true;
    } catch {
      // The record acknowledgment is already known. A cleanup failure cannot
      // turn it into a failed save; Home still exposes the retained recovery copy.
      return false;
    }
  }

  chooseProjectFolder() {
    return this.client.chooseProjectFolder();
  }

  async harnessProbe(params: HarnessParams) {
    const result = await this.call({ method: 'harness_probe', params });
    if (!result || result.kind !== 'probe' || Object.keys(result).length !== 2 ||
      !result.data || Object.keys(result.data).length !== 1) {
      throw new Error('Harness discovery was not returned.');
    }
    return validateHarnessProbe(result.data.report, params);
  }

  async harnessExecutionStart(params: HarnessExecutionParams) {
    return this.harnessExecution('harness_execution_start', params);
  }

  async harnessExecutionStatus(params: HarnessExecutionParams) {
    return this.harnessExecution('harness_execution_status', params);
  }

  private async harnessExecution(method: 'harness_execution_start' | 'harness_execution_status', params: HarnessExecutionParams) {
    const result = await this.call({ method, params });
    const status = validateHarnessExecution(harnessResult(result, 'harness_execution', 'status'));
    if (status.planId !== params.planId || status.action !== params.action) throw new Error('Setup operation identity changed.');
    return status;
  }

  async harnessExecutionCurrent() {
    const result = await this.call({ method: 'harness_execution_current', params: {} });
    const value = harnessResult(result, 'harness_execution_current', 'status');
    return value === null ? null : validateHarnessExecution(value);
  }

  async harnessSetupGet(planId: PlanId) {
    const result = await this.call({ method: 'harness_setup_get', params: { planId } });
    const setup = validateHarnessSetupRecord(harnessResult(result, 'harness_setup', 'setup'));
    if (setup.plan.planId !== planId) throw new Error('Saved setup identity changed.');
    return setup;
  }

  async harnessSetupsList(after: PlanId | null = null) {
    const result = await this.call({ method: 'harness_setups_list', params: { after } });
    const page = validateHarnessSetupsPage(harnessResult(result, 'harness_setups', 'page'));
    if (after !== null && (page.setups.some(item => item.planId >= after) || (page.nextAfter !== null && page.nextAfter >= after))) {
      throw new Error('Setup history did not advance.');
    }
    return page;
  }

  async harnessPrepare(params: HarnessPrepareParams) {
    return this.harnessPreparation('harness_prepare', params);
  }

  async harnessPreparationStatus(params: HarnessPrepareParams) {
    return this.harnessPreparation('harness_preparation_status', params);
  }

  async harnessPreparationCancel(params: HarnessPrepareParams) {
    return this.harnessPreparation('harness_preparation_cancel', params);
  }

  private async harnessPreparation(method: 'harness_prepare' | 'harness_preparation_status' | 'harness_preparation_cancel', params: HarnessPrepareParams) {
    const request: LocalRequest = method === 'harness_prepare' ? { method, params } : { method, params: { operationId: params.operationId } };
    const result = await this.call(request);
    const status = validateHarnessPreparation(harnessResult(result, 'harness_preparation', 'status'));
    if (status.operationId !== params.operationId || status.selection.harness !== params.selection.harness ||
      status.selection.projectId !== params.selection.projectId || status.selection.hermesProfile !== params.selection.hermesProfile) {
      throw new Error('Preparation does not match the selected operation.');
    }
    return status;
  }

  async harnessPreparedPreview(params: HarnessPrepareParams) {
    const result = await this.call({ method: 'harness_prepared_preview', params });
    return validateHarnessPlan(harnessResult(result, 'plan', 'plan'), params.selection);
  }

  async harnessPreview(params: HarnessParams) {
    const result = await this.call({ method: 'harness_preview', params });
    if (!result || result.kind !== 'plan' || Object.keys(result).length !== 2 ||
      !result.data || Object.keys(result.data).length !== 1) {
      throw new Error('Setup preview was not returned.');
    }
    return validateHarnessPlan(result.data.plan, params);
  }

  async harnessApply(planId: PlanId) {
    requireHarnessAcknowledgment(await this.call({ method: 'harness_apply', params: { planId } }));
  }

  async harnessRollback(planId: PlanId) {
    requireHarnessAcknowledgment(await this.call({ method: 'harness_rollback', params: { planId } }));
  }

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
    const folder = nativePath(path);
    const pathKey = `${folder.platform}:${folder.bytes}`;
    const project: ProjectIdentity = this.pendingProject?.name === name && this.pendingProject.pathKey === pathKey ? this.pendingProject.project : {
      projectId: uuidV7() as ProjectId,
      githubRepositoryId: null,
      gitRemoteFingerprint: null,
      monorepoSubdirectory: null,
      name,
    };
    this.pendingProject = { name, pathKey, project };
    const result = await this.call({ method: 'project_register', params: { project, path: folder } });
    if (result.kind !== 'empty') unexpected(result);
    this.pendingProject = null;
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

  async createMemory(projectId: string | null, title: string, bodyMarkdown: string, attempt?: object) {
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
      }, attempt),
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

  async createTask(projectId: string, title: string, bodyMarkdown: string, attempt?: object) {
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
      }, attempt),
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

  private call(request: LocalRequest, attempt?: object) {
    switch (request.method) {
      case 'memory_create':
      case 'memory_update':
      case 'memory_archive':
      case 'task_upsert':
      case 'task_transition':
      case 'task_complete':
      case 'candidate_review':
        return this.mutation(request, attempt);
      default:
        return this.client.call(request);
    }
  }

  private async mutation(
    request: DesktopWrite,
    attempt?: object,
  ): Promise<LocalResult> {
    // Retain the identity until a usable acknowledgment arrives. Only an
    // explicit identical request replays it; changed input gets a new identity.
    let draft = 0;
    if (attempt) {
      draft = this.draftAttempts.get(attempt) ?? this.nextDraftAttempt++;
      this.draftAttempts.set(attempt, draft);
    }
    const key = JSON.stringify({ draft, method: request.method, params: { ...request.params, operationId: undefined } });
    const operationId = this.pendingOperations.get(key)?.operationId ?? request.params.operationId;
    this.pendingOperations.set(key, { operationId, createsRecord: request.method === 'memory_create' ||
      (request.method === 'task_upsert' && request.params.taskId === null) });
    const write = { ...request, params: { ...request.params, operationId } } as DesktopWrite;
    let prepared: LocalResult;
    try {
      prepared = await this.client.call({ method: 'desktop_write_prepare', params: { write } });
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'quota_exceeded') {
        throw new RecoveryStorageFullError();
      }
      throw error;
    }
    if (prepared.kind !== 'empty') unexpected(prepared);
    const result = await this.client.call(write);
    const record = writeRecord(write, result);
    // A later acknowledged edit/archive/completion proves this creation was
    // observed. A future identical creation must be a new record.
    this.retirePending(operationId, record.id);
    await this.cleanupWrite(operationId);
    return result;
  }
}

function writeRecord(write: DesktopWrite, result: LocalResult) {
  if ((result.kind === 'tasks' && result.data.tasks.length !== 1) ||
    (result.kind === 'candidates' && result.data.candidates.length !== 1)) {
    throw new Error('The change acknowledgment contained unrelated records.');
  }
  const record = write.method.startsWith('memory_') ? memoryResult(result)
    : write.method === 'candidate_review' ? candidateResult(result) : taskResult(result);
  const expectedId = write.method === 'memory_create' ? write.params.operationId
    : write.method === 'memory_update' || write.method === 'memory_archive' ? write.params.memoryId
      : write.method === 'candidate_review' ? write.params.candidateId
        : write.method === 'task_upsert' ? write.params.taskId ?? write.params.operationId : write.params.taskId;
  if (record.id !== expectedId) throw new Error('The change acknowledgment did not match the recovery copy.');
  if (write.method === 'candidate_review') {
    if (!('state' in record) || record.state !== (write.params.accepted ? 'accepted' : 'rejected')) {
      throw new Error('The suggestion decision was not acknowledged.');
    }
  } else if (!('revision' in record) || record.revision !== write.params.operationId) {
    throw new Error('The change revision was not acknowledged.');
  }
  return record;
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

function candidateResult(result: LocalResult) {
  return result.kind === 'candidates' && result.data.candidates[0]
    ? result.data.candidates[0] : unexpected(result);
}

function unexpected(result: LocalResult): never {
  throw new Error(`Unexpected local result: ${result.kind}`);
}

function unexpectedNativeResult(result: never): never {
  throw new Error(`Unexpected native recovery result: ${String(result)}`);
}



function nativePath(path: string) {
  const macos = navigator.userAgent.includes('Mac');
  // Explorer's Copy as path wraps Windows paths in quotes. These cannot be
  // filename characters on Windows, but they are valid on macOS.
  if (!macos && path.startsWith('"') && path.endsWith('"')) path = path.slice(1, -1);
  const bytes = macos
    ? new TextEncoder().encode(path)
    : new Uint8Array(path.length * 2);
  if (!macos) {
    const view = new DataView(bytes.buffer);
    // Windows paths carry UTF-16 code units, including surrogate pairs and
    // unpaired surrogates. Iterating code points would drop the second unit.
    for (let index = 0; index < path.length; index += 1) {
      view.setUint16(index * 2, path.charCodeAt(index), true);
    }
  }
  const binary = [...bytes].map((byte) => String.fromCharCode(byte)).join('');
  return {
    platform: macos ? ('macos' as const) : ('windows' as const),
    bytes: btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '') as Base64Url,
    display: path,
  };
}
