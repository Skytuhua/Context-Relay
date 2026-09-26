import { Component, type ErrorInfo, type ReactNode } from 'react';

type Props = { children: ReactNode; label: string };
type State = { failure: Error | null };

/**
 * Contain a render failure to one part of the window.
 *
 * The workspace holds unsaved form text in refs, which hold no recoverable
 * copy, so a single throw during render unmounts everything and the user loses
 * every half-written note with no explanation. A per-screen boundary keeps the
 * sidebar, toolbar and project switcher alive so they can navigate away, and
 * reports the failure instead of showing a blank window.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { failure: null };

  static getDerivedStateFromError(failure: Error): State {
    return { failure };
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
