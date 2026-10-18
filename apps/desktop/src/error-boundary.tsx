import { Component, type ErrorInfo, type ReactNode } from 'react';

type Props = { children: ReactNode; label: string; resetKey?: string };
type State = { failure: Error | null };

/**
 * Contain a render failure to one part of the window.
 *
 * The workspace holds unsaved form text in refs, so unmounting the whole app
 * loses every half-written note. A per-screen boundary keeps the
 * sidebar, toolbar and project switcher alive so they can navigate away, and
 * reports the failure instead of showing a blank window.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { failure: null };

  static getDerivedStateFromError(failure: Error): State {
    return { failure };
  }

  componentDidUpdate(previous: Props) {
    if (this.state.failure && previous.resetKey !== this.props.resetKey) {
      this.setState({ failure: null });
    }
  }

  componentDidCatch(failure: Error, info: ErrorInfo) {
    // Keep the diagnostic detail out of the message the user reads. Component
    // stacks carry file paths, so only the screen label is shown.
    console.error(`Context Relay could not display ${this.props.label}.`, info.componentStack);
  }

  render() {
    if (this.state.failure) {
      return <div className="screen-error" role="alert">
        <h2>{this.props.label} could not be displayed</h2>
        <p>Your saved context and tasks are unchanged. Go to another page, or reopen this one to try again.</p>
        <button className="primary-action" type="button" onClick={() => this.setState({ failure: null })}>Try again</button>
      </div>;
    }
    return this.props.children;
  }
}
