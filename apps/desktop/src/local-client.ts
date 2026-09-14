import { invoke } from '@tauri-apps/api/core';

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
    return invoke<LocalResult>('local_request', { request });
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
