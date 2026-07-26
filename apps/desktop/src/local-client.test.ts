import { beforeEach, expect, it, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));

import { LocalClient } from './local-client';

beforeEach(() => {
  invoke.mockReset();
});

it('forwards only the typed request through the local_request command', async () => {
  const response = { kind: 'projects', data: { projects: [] } } as const;
  invoke.mockResolvedValue(response);
  const request = { method: 'projects_list', params: {} } as const;

  await expect(new LocalClient().call(request)).resolves.toEqual(response);
  expect(invoke).toHaveBeenCalledWith('local_request', { request });
});
