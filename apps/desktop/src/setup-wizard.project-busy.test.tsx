import { useState } from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';

import type { ProjectIdentity } from './bindings';
import { defaultPreferences, type SetupProgress } from './desktop-preferences';
import { SetupWizard } from './setup-wizard';
import type { WorkspaceGateway } from './workspace';

const first = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'Existing project' } as ProjectIdentity;
const second = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073981', name: 'Another project' } as ProjectIdentity;
const created = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073982', name: 'New project' } as ProjectIdentity;

afterEach(cleanup);

it('holds project selection during registration and continues with the project that was saved', async () => {
  let finishRegistration!: (project: ProjectIdentity) => void;
  const registration = new Promise<ProjectIdentity>(resolve => { finishRegistration = resolve; });
  const createProject = vi.fn(() => registration);
  const changed = vi.fn();
  const saved = vi.fn();
  const gateway = {
    createProject,
    harnessSetupsList: vi.fn(async () => ({ setups: [], nextAfter: null })),
  } as unknown as WorkspaceGateway;

  function Onboarding() {
    const [projects, setProjects] = useState([first, second]);
    const [progress, setProgress] = useState<SetupProgress>({
      ...defaultPreferences().setup,
      status: 'in_progress', step: 'project', harnesses: ['codex'], projectId: first.projectId,
    });
    return <SetupWizard gateway={gateway} projects={projects} progress={progress}
      onChange={next => { changed(next); setProgress(next); }}
      onProjectSaved={project => { saved(project); setProjects(current => [...current, project]); }}
      onFinishLater={() => undefined} onTour={() => undefined} onOpenGuide={() => undefined}
      renderConnection={project => <p>Review connection for {project.name}</p>}
      renderTest={() => <p>Read test</p>} />;
  }

  render(<Onboarding />);
  expect(screen.getByRole('radio', { name: first.name })).toBeChecked();
  const otherProject = screen.getByRole<HTMLInputElement>('radio', { name: second.name });
  expect(otherProject).toBeEnabled();
  fireEvent.change(screen.getByRole('textbox', { name: 'Project folder' }), { target: { value: 'C:\\work\\new-project' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Project name' }), { target: { value: created.name } });
  fireEvent.click(screen.getByRole('button', { name: 'Add project' }));

  expect(createProject).toHaveBeenCalledExactlyOnceWith(created.name, 'C:\\work\\new-project');
  for (const radio of screen.getAllByRole('radio')) expect(radio).toBeDisabled();
  for (const name of ['Back', 'Continue', 'Finish later']) expect(screen.getByRole('button', { name })).toBeDisabled();
  // A native click obeys the disabled control, including in the DOM emulator.
  act(() => { otherProject.click(); });
  expect(changed).not.toHaveBeenCalled();
  expect(screen.getByRole('radio', { name: first.name })).toBeChecked();
  expect(saved).not.toHaveBeenCalled();

  await act(async () => { finishRegistration(created); await registration; });
  expect(saved).toHaveBeenCalledExactlyOnceWith(created);
  expect(changed).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ projectId: created.projectId, step: 'project' }));
  expect(screen.getByRole('radio', { name: created.name })).toBeChecked();
  expect(otherProject).not.toBeChecked();
  for (const radio of screen.getAllByRole('radio')) expect(radio).toBeEnabled();
  expect(screen.getByRole('textbox', { name: 'Project name' })).toHaveValue('');
  expect(screen.getByRole('textbox', { name: 'Project folder' })).toHaveValue('');

  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  expect(await screen.findByText(`Review connection for ${created.name}`)).toBeVisible();
  expect(changed).toHaveBeenLastCalledWith(expect.objectContaining({ projectId: created.projectId, step: 'connect' }));
  expect(createProject).toHaveBeenCalledTimes(1);
});
