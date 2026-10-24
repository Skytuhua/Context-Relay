import { invoke } from '@tauri-apps/api/core';
import { assertMemoryCandidate, assertMemoryRecord, assertProjectIdentity, assertTaskRecord } from './protocol-validation';

import type {
  LocalRequest,
  LocalResult,
  RecoveryEnrollmentConfirmParams,
  RecoveryEnrollmentHostBeginResult,
  RecoveryEnrollmentHostConfirmResult,
  RecoveryRestoreStatus,
  RecoveryHistorySelectParams,
} from './bindings';

export class LocalClient {
  recoveryHistoryUnlock(params: RecoveryHistorySelectParams): Promise<RecoveryRestoreStatus | null> {
    return invoke<RecoveryRestoreStatus | null>('recovery_history_unlock', { params });
  }
  recoveryRestoreBegin(): Promise<RecoveryRestoreStatus | null> {
    return invoke<RecoveryRestoreStatus | null>('recovery_restore_begin');
  }

  chooseProjectFolder(): Promise<string | null> {
    return invoke<string | null>('choose_project_folder');
  }

  async call(request: LocalRequest): Promise<LocalResult> {
    if (
      request.method === 'recovery_enrollment_begin' ||
      request.method === 'recovery_restore_begin' ||
      request.method === 'recovery_history_unlock' ||
      request.method === 'recovery_enrollment_confirm'
    ) {
      throw new Error('Recovery approval requires the dedicated native recovery command.');
    }
    switch (request.method) {
      case 'projects_list': {
        const projects = await this.listPages(cursor => ({ method: 'projects_list_page', params: { cursor } }),
          'projects', assertProjectIdentity, project => project.projectId);
        projects.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : a.projectId.localeCompare(b.projectId));
        return { kind: 'projects', data: { projects } };
      }
      case 'memory_list':
        return { kind: 'memories', data: { memories: await this.listPages(
          cursor => ({ method: 'memory_list_page', params: { ...request.params, cursor } }),
          'memories', assertMemoryRecord, memory => memory.id) } };
      case 'candidates_list':
        return { kind: 'candidates', data: { candidates: await this.listPages(
          cursor => ({ method: 'candidates_list_page', params: { ...request.params, cursor } }),
          'candidates', assertMemoryCandidate, candidate => candidate.id) } };
      case 'tasks_list':
        return { kind: 'tasks', data: { tasks: await this.listPages(
          cursor => ({ method: 'tasks_list_page', params: { ...request.params, cursor } }),
          'tasks', assertTaskRecord, task => task.id) } };
    }
    return invoke<LocalResult>('local_request', { request });
  }

  private async listPages<T>(
    request: (cursor: string | null) => LocalRequest,
    field: string,
    assertRecord: (value: unknown) => asserts value is T,
    recordId: (record: T) => string,
  ): Promise<T[]> {
    const records: T[] = [];
    const cursors = new Set<string>();
    let cursor: string | null = null;
    let lastId = '';
    do {
      const result: { kind: string; data: { page: Record<string, unknown> } } = await invoke(
        'local_request', { request: request(cursor) });
      const page: Record<string, unknown> | undefined = result?.data?.page;
      const items = page?.[field];
      const next: unknown = page?.nextCursor;
      if (result?.kind !== `${field}_page` || !page || Object.keys(page).length !== 2 ||
        !Array.isArray(items) || items.length > 128 ||
        !(next === null || (typeof next === 'string' && next.length > 0 && next.length <= 256 &&
          [...next].every(character => character.charCodeAt(0) <= 127))) ||
        (next !== null && (items.length === 0 || cursors.has(next))) ||
        new TextEncoder().encode(JSON.stringify(page)).byteLength > 7 * 1024 * 1024) {
        throw new Error('The local list page was not confirmed.');
      }
      for (const item of items) {
        assertRecord(item);
        const id = recordId(item);
        if (id <= lastId) throw new Error('The local list page was not confirmed.');
        lastId = id;
        records.push(item);
      }
      cursor = next;
      if (cursor !== null) cursors.add(cursor);
    } while (cursor !== null);
    return records;
  }

  recoveryEnrollmentBegin(): Promise<RecoveryEnrollmentHostBeginResult> {
    return invoke<RecoveryEnrollmentHostBeginResult>('recovery_enrollment_begin');
  }

  recoveryEnrollmentConfirm(
    params: RecoveryEnrollmentConfirmParams,
  ): Promise<RecoveryEnrollmentHostConfirmResult> {
    return invoke<RecoveryEnrollmentHostConfirmResult>('recovery_enrollment_confirm', { params });
  }
}
