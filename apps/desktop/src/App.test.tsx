import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import App from './App';

const destinations = [
  'Home',
  'Projects',
  'Memory',
  'Review queue',
  'Tasks',
  'Harnesses',
  'Packages',
  'Activity',
  'Devices',
  'Settings',
] as const;

describe('App', () => {
  beforeEach(() => {
    HTMLDialogElement.prototype.showModal = function showModal() {
      this.setAttribute('open', '');
    };
    HTMLDialogElement.prototype.close = function close() {
      this.removeAttribute('open');
      this.dispatchEvent(new Event('close'));
    };
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('exposes all workspace destinations and focuses each selected screen heading', () => {
    render(<App />);

    const navigation = screen.getByRole('navigation', { name: 'Workspace' });
    const buttons = within(navigation).getAllByRole('button');
    expect(buttons.map((button) => button.textContent)).toEqual(destinations);
    expect(screen.getByRole('button', { name: 'Home' })).toHaveAttribute('aria-current', 'page');

    expect(screen.getAllByRole('link')[0]).toHaveTextContent('Skip to workspace');
    expect(screen.getAllByRole('link')[0]).toHaveAttribute('href', '#workspace-main');
    const status = screen.getByRole('status');
    expect(status).toHaveTextContent('The encrypted daemon boundary is local');
    expect(status).toHaveTextContent('Full workspace services are still arriving');
    expect(status).not.toHaveTextContent(/loaded/i);
    const capabilityStatus = screen.getByRole('list', { name: 'Local capability status' });
    expect(within(capabilityStatus).getAllByRole('listitem').map((item) => item.textContent)).toEqual([
      'Project path identification is available through the local daemon boundary.',
      'Single-memory reads are available through the local daemon boundary.',
      'Full workspace services remain deferred in this build.',
    ]);

    for (const destination of destinations.slice(1)) {
      fireEvent.click(screen.getByRole('button', { name: destination }));
      const heading = screen.getByRole('heading', { level: 1, name: destination });
      expect(heading).toHaveFocus();
      expect(screen.getByRole('button', { name: destination })).toHaveAttribute(
        'aria-current',
        'page',
      );
    }
  });

  it('validates memory input without echoing submitted plaintext into status state', () => {
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: 'Memory' }));

    const form = screen.getByRole('form', { name: 'New memory' });
    const title = screen.getByRole('textbox', { name: 'Title' });
    const body = screen.getByRole('textbox', { name: 'Memory' });

    fireEvent.submit(form);
    expect(title).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByRole('alert')).toHaveTextContent('Enter a title.');

    fireEvent.change(title, { target: { value: 'Private title canary' } });
    fireEvent.submit(form);
    expect(body).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByRole('alert')).toHaveTextContent('Enter memory text.');

    fireEvent.change(body, { target: { value: 'Bulk plaintext canary' } });
    fireEvent.submit(form);
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent(/^This service is not available in this build$/);
    expect(alert).not.toHaveTextContent('Private title canary');
    expect(alert).not.toHaveTextContent('Bulk plaintext canary');
  });

  it('validates task input without echoing submitted plaintext into status state', () => {
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: 'Tasks' }));

    const form = screen.getByRole('form', { name: 'New task' });
    const title = screen.getByRole('textbox', { name: 'Task title' });

    fireEvent.submit(form);
    expect(title).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByRole('alert')).toHaveTextContent('Enter a task title.');

    fireEvent.change(title, { target: { value: 'Private task canary' } });
    fireEvent.submit(form);
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent(/^This service is not available in this build$/);
    expect(alert).not.toHaveTextContent('Private task canary');
  });

  it('does not persist or log valid memory and task submissions', () => {
    const storageSpy = vi.spyOn(Storage.prototype, 'setItem');
    const logSpy = vi.spyOn(console, 'log');
    const infoSpy = vi.spyOn(console, 'info');
    const debugSpy = vi.spyOn(console, 'debug');

    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: 'Memory' }));
    fireEvent.change(screen.getByRole('textbox', { name: 'Title' }), {
      target: { value: 'Private title canary' },
    });
    fireEvent.change(screen.getByRole('textbox', { name: 'Memory' }), {
      target: { value: 'Bulk plaintext canary' },
    });
    fireEvent.submit(screen.getByRole('form', { name: 'New memory' }));

    fireEvent.click(screen.getByRole('button', { name: 'Tasks' }));
    fireEvent.change(screen.getByRole('textbox', { name: 'Task title' }), {
      target: { value: 'Private task canary' },
    });
    fireEvent.submit(screen.getByRole('form', { name: 'New task' }));

    expect(storageSpy).not.toHaveBeenCalled();
    expect(logSpy).not.toHaveBeenCalled();
    expect(infoSpy).not.toHaveBeenCalled();
    expect(debugSpy).not.toHaveBeenCalled();
  });

  it('restores security dialog trigger focus after close and cancel', () => {
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: 'Settings' }));

    const trigger = screen.getByRole('button', { name: 'Security details' });
    fireEvent.click(trigger);
    const dialog = screen.getByRole('dialog', { name: 'Local security details' });
    expect(dialog).toHaveAttribute('open');

    fireEvent.click(screen.getByRole('button', { name: 'Close security details' }));
    expect(dialog).not.toHaveAttribute('open');
    expect(trigger).toHaveFocus();

    fireEvent.click(trigger);
    expect(dialog).toHaveAttribute('open');
    const cancelEvent = new Event('cancel', { cancelable: true });
    fireEvent(dialog, cancelEvent);
    expect(cancelEvent.defaultPrevented).toBe(true);
    expect(dialog).not.toHaveAttribute('open');
    expect(trigger).toHaveFocus();
  });
});
