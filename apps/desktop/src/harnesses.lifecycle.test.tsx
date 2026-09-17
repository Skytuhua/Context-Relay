import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { HarnessesScreen } from './harnesses';
import type { HarnessSetupsPage, HarnessSetupSummary, PlanId, ProjectIdentity } from './bindings';
import type { HarnessGateway } from './harness-gateway';

const native = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => native);
const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'My project' } as ProjectIdentity;
const other = { ...project, projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073981' as ProjectIdentity['projectId'], name: 'Other project' };
const id = (number: number) => `018f22e2-79b0-7cc8-98c4-${number.toString(16).padStart(12, '0')}` as PlanId;
const summary = (number: number): HarnessSetupSummary => ({ planId: id(number), harness: 'codex', harnessProfile: null, targetScopes: [{ scope: 'project', projectId: project.projectId }], state: 'applied', createdAt: '1900000000000', expiresAt: '1900000060000' } as HarnessSetupSummary);
function fixture() {
  const api = { harnessExecutionCurrent: vi.fn(async () => null), harnessSetupsList: vi.fn<(after?: PlanId | null) => Promise<HarnessSetupsPage>>(async () => ({ setups: [summary(50)], nextAfter: id(40) })) };
  return { api, gateway: api as unknown as HarnessGateway };
}
const props = { projects: [project, other], preferredProjectId: project.projectId };
let clipboard: PropertyDescriptor | undefined;
beforeEach(() => { clipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard'); });
afterEach(() => {
  cleanup(); vi.restoreAllMocks(); native.invoke.mockReset();
  if (clipboard) Object.defineProperty(navigator, 'clipboard', clipboard);
  else Reflect.deleteProperty(navigator, 'clipboard');
});

it.each(['resolve', 'reject'] as const)('ignores an obsolete load-more %s after leaving and refreshing history', async result => {
  const { api, gateway } = fixture();
  let resolve!: (page: HarnessSetupsPage) => void;
  let reject!: (reason: unknown) => void;
  const oldPage = new Promise<HarnessSetupsPage>((done, fail) => { resolve = done; reject = fail; });
  const view = render(<HarnessesScreen {...props} gateway={gateway} />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Load more setups' })).toBeEnabled());
  api.harnessSetupsList.mockImplementationOnce(() => oldPage);
  fireEvent.click(screen.getByRole('button', { name: 'Load more setups' }));
  view.rerender(<HarnessesScreen {...props} gateway={gateway} active={false} />);
  api.harnessSetupsList.mockResolvedValue({ setups: [summary(90)], nextAfter: id(80) });
  view.rerender(<HarnessesScreen {...props} gateway={gateway} />);
  await screen.findByRole('heading', { name: /setup 0000005A/ });
  await act(async () => {
    if (result === 'resolve') resolve({ setups: [summary(30)], nextAfter: id(20) });
    else reject(new Error('old history request failed'));
  });
  expect(screen.queryByRole('heading', { name: /setup 0000001E/ })).not.toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Load more setups' }));
  await waitFor(() => expect(api.harnessSetupsList).toHaveBeenLastCalledWith(id(80)));
});

it('offers macOS a launch command for Terminal instead of an unsupported Open action', async () => {
  vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue('Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)');
  const writeText = vi.fn(async () => {});
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
  native.invoke.mockResolvedValue("cd '/project' && '/opt/codex'");
  const { gateway } = fixture();
  render(<HarnessesScreen {...props} gateway={gateway} />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Copy command' })).toBeEnabled());
  expect(screen.queryByRole('button', { name: 'Open Codex for this project' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Copy command' }));
  await screen.findByText(/Command copied.*Terminal/);
  expect(screen.queryByText(/PowerShell/)).not.toBeInTheDocument();
  expect(native.invoke).toHaveBeenCalledWith('harness_copy_command', { selection: { harness: 'codex', projectId: project.projectId, hermesProfile: null } });
  expect(writeText).toHaveBeenCalledTimes(1);
});

it.each(['resolve', 'reject'] as const)('ignores a late native launch %s after the project changes', async result => {
  vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue('Mozilla/5.0 (Windows NT 10.0; Win64; x64)');
  let resolve!: () => void;
  let reject!: (reason: unknown) => void;
  native.invoke.mockImplementation(() => new Promise<void>((done, fail) => { resolve = done; reject = fail; }));
  const { gateway } = fixture();
  const view = render(<HarnessesScreen {...props} gateway={gateway} />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Open Codex for this project' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Open Codex for this project' }));
  view.rerender(<HarnessesScreen {...props} preferredProjectId={other.projectId} gateway={gateway} />);
  await act(async () => { if (result === 'resolve') resolve(); else reject(new Error('PRIVATE native launch error')); });
  expect(screen.queryByText(/Harness window opened/)).not.toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
