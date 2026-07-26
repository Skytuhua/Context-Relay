import { invoke } from '@tauri-apps/api/core';

import type { LocalRequest, LocalResult } from './bindings';

export class LocalClient {
  call(request: LocalRequest): Promise<LocalResult> {
    return invoke<LocalResult>('local_request', { request });
  }
}
