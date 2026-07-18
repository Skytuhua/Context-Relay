import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import App from './App';

describe('App', () => {
  it('identifies the pre-alpha workspace and unfinished local setup', () => {
    render(<App />);

    expect(screen.getByRole('heading', { level: 1, name: 'Context Relay' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: 'Pre-alpha workspace' })).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent(
      'Local encrypted context setup is not implemented yet.',
    );
  });
});
