import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { SetupWizard } from './setup-wizard';
import { defaultPreferences } from './desktop-preferences';
import type { WorkspaceGateway } from './workspace';
import type { ProjectIdentity } from './bindings';

afterEach(cleanup);
const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'Installer verification 專案 🚀' } as ProjectIdentity;
const gateway = { harnessProbe: vi.fn(async () => ({ capability: 'missing', harnessVersion: null })) } as unknown as WorkspaceGateway;
const props = { gateway, projects: [project], progress: defaultPreferences().setup, onChange: vi.fn(), onProjectSaved: vi.fn(), onFinishLater: vi.fn(), onTour: vi.fn(), onOpenGuide: vi.fn(), renderConnection: () => <p>Connection controls</p>, renderTest: () => <p>Read test</p> };

it('explains harnesses, permits multiple selections and offers finishing later', async () => {
  const changed = vi.fn(); render(<SetupWizard {...props} onChange={changed} />);
  expect(screen.getByText(/A harness is the tool you work in/)).toBeVisible();
  expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
  fireEvent.click(screen.getByRole('checkbox', { name: /Codex/ }));
  expect(changed).toHaveBeenCalledWith(expect.objectContaining({ harnesses: ['codex'], status: 'in_progress' }));
  fireEvent.click(screen.getByRole('button', { name: 'Finish later' }));
  expect(props.onFinishLater).toHaveBeenCalled();
  await screen.findAllByText('Not installed');
});

it('requires choosing an existing project rather than silently choosing the first record', () => {
  render(<SetupWizard {...props} progress={{ ...props.progress, step: 'project', harnesses: ['codex'] }} />);
  expect(screen.getByRole('radio', { name: /Installer verification/ })).not.toBeChecked();
  expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
  fireEvent.click(screen.getByRole('radio', { name: /Installer verification/ }));
  expect(props.onChange).toHaveBeenCalledWith(expect.objectContaining({ projectId: project.projectId }));
});

it('explains a removed project when resuming a later step', () => {
  render(<SetupWizard {...props} projects={[]} progress={{ ...props.progress, step: 'test', projectId: project.projectId, harnesses: ['codex'] }} />);
  expect(screen.getByText(/Choose a project to continue/)).toBeVisible();
  expect(screen.queryByText('Read test')).not.toBeInTheDocument();
});

it('opens the replayable tour without submitting any setup operation', () => {
  render(<SetupWizard {...props} progress={{ ...props.progress, step: 'tour' }} />);
  fireEvent.click(screen.getByRole('button', { name: 'Show me the dashboard' }));
  expect(props.onTour).toHaveBeenCalled();
});
