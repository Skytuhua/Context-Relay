import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { DashboardTour, HelpScreen } from './help-tour';

afterEach(cleanup);
it('provides offline explanations and replay actions', () => {
  const onResumeSetup = vi.fn(), onStartTour = vi.fn();
  render(<HelpScreen onResumeSetup={onResumeSetup} onStartTour={onStartTour} />);
  expect(screen.getByRole('heading', { name: 'Saved context' })).toBeVisible();
  expect(screen.getByRole('heading', { name: 'Suggestions' })).toBeVisible();
  expect(screen.getByRole('heading', { name: 'Tasks' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Resume setup' }));
  fireEvent.click(screen.getByRole('button', { name: 'Start tour' }));
  expect(onResumeSetup).toHaveBeenCalledOnce();
  expect(onStartTour).toHaveBeenCalledOnce();
});

it('navigates all five parts, preserves accessible nonblocking controls, and finishes', () => {
  const onStep = vi.fn(), onClose = vi.fn(), onNavigate = vi.fn();
  const props = { onStep, onClose, onNavigate };
  const view = render(<DashboardTour step={0} {...props} />);
  expect(screen.getByRole('button', { name: 'Back' })).toBeDisabled();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  const destinations = ['home', 'memory', 'review', 'tasks', 'harnesses'];
  for (let step = 0; step < 5; step++) {
    view.rerender(<DashboardTour step={step} {...props} />);
    fireEvent.click(screen.getByRole('button', { name: /Show / }));
    expect(onNavigate).toHaveBeenLastCalledWith(destinations[step]);
    expect(screen.getByRole('status')).toHaveTextContent(`Part ${step + 1} of 5`);
    if (step < 4) {
      fireEvent.click(screen.getByRole('button', { name: 'Next' }));
      expect(onStep).toHaveBeenLastCalledWith(step + 1);
    }
  }
  fireEvent.click(screen.getByRole('button', { name: 'Back' }));
  expect(onStep).toHaveBeenLastCalledWith(3);
  fireEvent.click(screen.getByRole('button', { name: 'Finish tour' }));
  expect(onClose).toHaveBeenCalledOnce();
});

it('lets users skip at any point', () => {
  const onClose = vi.fn();
  render(<DashboardTour step={2} onStep={vi.fn()} onNavigate={vi.fn()} onClose={onClose} />);
  fireEvent.click(screen.getByRole('button', { name: 'Skip tour' }));
  expect(onClose).toHaveBeenCalledOnce();
});
