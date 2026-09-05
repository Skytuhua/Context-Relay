import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';

import App from './App';
import type { MemoryRecord, ProjectIdentity } from './bindings';
import type { WorkspaceGateway } from './workspace';

const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'Research' } as ProjectIdentity;
const gateway = {
  status: async () => ({ vault: 'unlocked', sync: 'offline' }),
  projects: async () => [],
  memories: async () => [],
  tasks: async () => [],
  candidates: async () => [],
} as unknown as WorkspaceGateway;

afterEach(cleanup);

it('guides a first project from folder selection to the next useful actions without duplicate saves', async () => {
  let finish!: (value: ProjectIdentity) => void;
  const createProject = vi.fn(() => new Promise<ProjectIdentity>((resolve) => { finish = resolve; }));
  const chooseProjectFolder = vi.fn().mockResolvedValue('C:\\Work\\Research 專案 🚀');
  render(<App gateway={{ ...gateway, createProject, chooseProjectFolder }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(await screen.findByRole('button', { name: 'Add your project folder' }));
  fireEvent.click(screen.getByRole('button', { name: 'Choose folder…' }));
  await act(async () => {});
  expect(screen.getByLabelText('Project folder')).toHaveValue('C:\\Work\\Research 專案 🚀');
  expect(screen.getByLabelText('Project name')).toHaveValue('Research 專案 🚀');
  const form = screen.getByRole('form', { name: 'Add project' });
  fireEvent.submit(form);
  fireEvent.submit(form);
  expect(createProject).toHaveBeenCalledTimes(1);
  expect(createProject).toHaveBeenCalledWith('Research 專案 🚀', 'C:\\Work\\Research 專案 🚀');
  expect(screen.getByRole('button', { name: 'Adding project…' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Home' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Home' }));
  expect(form).toBeVisible();
  await act(async () => { finish(project); });
  expect(screen.getByRole('button', { name: 'Connect a harness' })).toBeVisible();
  expect(screen.getByRole('button', { name: 'Save your first context' })).toBeVisible();
});

it('connects the newly added project even when another project already exists', async () => {
  const second = { ...project, projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073981', name: 'Website' } as ProjectIdentity;
  render(<App gateway={{ ...gateway, projects: async () => [project], createProject: async () => second }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Projects' }));
  fireEvent.change(screen.getByLabelText('Project name'), { target: { value: second.name } });
  fireEvent.change(screen.getByLabelText('Project folder'), { target: { value: 'C:\\Work\\Website' } });
  fireEvent.submit(screen.getByRole('form', { name: 'Add project' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Connect a harness' }));
  expect(screen.getByRole('combobox', { name: 'Project' })).toHaveValue(second.projectId);
});

it('preserves a chosen name and folder when the folder picker is canceled', async () => {
  const chooseProjectFolder = vi.fn().mockResolvedValue(null);
  render(<App gateway={{ ...gateway, chooseProjectFolder }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(await screen.findByRole('button', { name: 'Add your project folder' }));
  fireEvent.change(screen.getByLabelText('Project name'), { target: { value: 'My name' } });
  fireEvent.change(screen.getByLabelText('Project folder'), { target: { value: 'C:\\Work' } });
  fireEvent.click(screen.getByRole('button', { name: 'Choose folder…' }));
  await act(async () => {});
  expect(screen.getByLabelText('Project name')).toHaveValue('My name');
  expect(screen.getByLabelText('Project folder')).toHaveValue('C:\\Work');
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('ignores a late record load after switching projects', async () => {
  const second = { ...project, projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073981', name: 'Website' } as ProjectIdentity;
  let finishOld!: (value: MemoryRecord[]) => void;
  const oldNote = { id: 'old-note', title: 'Old project note', bodyMarkdown: 'Old content' } as MemoryRecord;
  const currentNote = { ...oldNote, id: 'new-note', title: 'Website note' } as MemoryRecord;
  render(<App gateway={{ ...gateway, projects: async () => [project, second], memories: (id) => id === project.projectId ? new Promise((resolve) => { finishOld = resolve; }) : Promise.resolve([currentNote]) }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Saved context' }));
  fireEvent.click(screen.getByRole('button', { name: 'Projects' }));
  fireEvent.click(screen.getByRole('button', { name: 'Website' }));
  fireEvent.click(screen.getByRole('button', { name: 'Saved context' }));
  await screen.findByText('Website note');
  await act(async () => { finishOld([oldNote]); });
  expect(screen.getByText('Website note')).toBeVisible();
  expect(screen.queryByText('Old project note')).not.toBeInTheDocument();
});

it('keeps an acknowledged new context visible when an older list arrives', async () => {
  let finishList!: (value: MemoryRecord[]) => void;
  const saved = { id: 'saved-note', title: 'New decision', bodyMarkdown: 'Use plain language.' } as MemoryRecord;
  const existing = { ...saved, id: 'existing-note', title: 'Earlier decision' } as MemoryRecord;
  const memories = vi.fn().mockImplementationOnce(() => new Promise((resolve) => { finishList = resolve; })).mockResolvedValue([saved, existing]);
  render(<App gateway={{ ...gateway, projects: async () => [project], memories, createMemory: async () => saved }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Saved context' }));
  const form = screen.getByRole('form', { name: 'New context' });
  fireEvent.change(within(form).getByLabelText('Title'), { target: { value: saved.title } });
  fireEvent.change(within(form).getByLabelText('What should your AI remember?'), { target: { value: saved.bodyMarkdown } });
  fireEvent.submit(form);
  await screen.findByText('Context saved');
  await act(async () => { finishList([]); });
  expect(screen.getByText('New decision')).toBeVisible();
  expect(screen.getByText('Earlier decision')).toBeVisible();
  expect(screen.queryByText('Loading your saved records…')).not.toBeInTheDocument();
});

it('uses the current project after selecting a different AI project and switching back', async () => {
  const second = { ...project, projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073981', name: 'Website' } as ProjectIdentity;
  render(<App gateway={{ ...gateway, projects: async () => [project, second] }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Connect a harness' }));
  fireEvent.change(screen.getByRole('combobox', { name: 'Project' }), { target: { value: second.projectId } });
  fireEvent.click(screen.getByRole('button', { name: 'Home' }));
  fireEvent.change(screen.getByRole('combobox', { name: 'Current project' }), { target: { value: second.projectId } });
  fireEvent.change(screen.getByRole('combobox', { name: 'Current project' }), { target: { value: project.projectId } });
  fireEvent.click(screen.getByRole('button', { name: 'Connect a harness' }));
  expect(screen.getByRole('combobox', { name: 'Project' })).toHaveValue(project.projectId);
});

it('reports an empty-search load failure and ignores a late failure after navigation', async () => {
  let reject!: (error: Error) => void;
  const memories = vi.fn().mockResolvedValueOnce([]).mockRejectedValueOnce(new Error('private details')).mockImplementationOnce(() => new Promise((_, fail) => { reject = fail; }));
  render(<App gateway={{ ...gateway, memories }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Saved context' }));
  await act(async () => {});
  fireEvent.submit(screen.getByRole('search', { name: 'Context search' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Search could not finish.');
  expect(screen.getByRole('alert')).not.toHaveTextContent('private details');
  fireEvent.submit(screen.getByRole('search', { name: 'Context search' }));
  fireEvent.click(screen.getByRole('button', { name: 'Home' }));
  await act(async () => { reject(new Error('late failure')); });
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('explains the missing project before offering a task form', async () => {
  render(<App gateway={gateway} />);
  await screen.findByRole('button', { name: 'Add your project folder' });
  fireEvent.click(screen.getByRole('button', { name: 'Tasks' }));
  expect(screen.queryByRole('form', { name: 'New task' })).not.toBeInTheDocument();
  expect(screen.getByText('Tasks belong to a project. Add its folder first.')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Add a project' }));
  expect(screen.getByRole('form', { name: 'Add project' })).toBeVisible();
});

it('keeps an unsaved context draft and explains a failed save without exposing native details', async () => {
  let reject!: (error: unknown) => void;
  const createMemory = vi.fn(() => new Promise<never>((_, fail) => { reject = fail; }));
  render(<App gateway={{ ...gateway, projects: async () => [project], createMemory }} />);
  await screen.findByRole('button', { name: 'Connect a harness' });
  fireEvent.click(screen.getByRole('button', { name: 'Saved context' }));
  await act(async () => {});
  const form = screen.getByRole('form', { name: 'New context' });
  fireEvent.change(within(form).getByLabelText('Title'), { target: { value: 'Preference' } });
  fireEvent.change(within(form).getByLabelText('What should your AI remember?'), { target: { value: 'Use plain language.' } });
  fireEvent.submit(form);
  fireEvent.submit(form);
  expect(createMemory).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  await act(async () => { reject({ code: 'internal', message: 'private native details' }); });
  expect(screen.getByRole('alert')).toHaveTextContent('Your draft is still here');
  expect(screen.getByRole('alert')).not.toHaveTextContent('private native details');
  expect(within(form).getByLabelText('What should your AI remember?')).toHaveValue('Use plain language.');
});
