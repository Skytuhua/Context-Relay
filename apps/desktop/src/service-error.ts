export const SERVICE_UPDATE_GUIDANCE = 'Context Relay and its local service use different versions. Close Context Relay, run the latest installer, then reopen it.';

/** Why the app could not reach its local service, and what the user can do about it. */
export type ConnectionFailureReason =
  | 'version-mismatch'
  | 'service-not-running'
  | 'service-unreachable'
  | 'unknown';

export interface ConnectionFailureGuidance {
  readonly reason: ConnectionFailureReason;
  /** One sentence, written for someone who is not a developer. */
  readonly message: string;
  /** What to try next, in order. Empty when there is nothing useful to suggest. */
  readonly steps: readonly string[];
  /** True when retrying the same request could plausibly work. */
  readonly retryable: boolean;
}

export function isServiceVersionMismatch(error: unknown): boolean {
  return !!error && typeof error === 'object' && 'code' in error && error.code === 'protocol_version_unsupported';
}

// The daemon answers with a structured `code` from the protocol's ErrorCode set
// (see bindings.ts). Match those directly so classification does not depend on
// the wording of an English message, then fall back to text for the transport
// failures the bridge itself produces.
const NOT_RUNNING_CODES = new Set(['daemon_not_running', 'service_not_running', 'not_running', 'no_such_process']);
const UNREACHABLE_CODES = new Set(['timeout', 'busy', 'connection_refused', 'pipe_broken', 'unreachable']);
// `safe_ipc_error` in src-tauri maps every non-version IPC failure, EndpointNotFound
// included, to code `internal` with this one message. It is by far the most common
// connection failure, so it is matched literally rather than left to guesswork.
const SERVICE_UNAVAILABLE = 'The local service is unavailable';
const NOT_RUNNING = new RegExp(
  `daemon|service[_ ](?:is[_ ])?not[_ ](?:running|started)|not running|no such (?:file|process)|${SERVICE_UNAVAILABLE}`,
  'i',
);
const UNREACHABLE = /connect|pipe|socket|timeout|timed out|unreachable|broken pipe|network/i;

/**
 * Turns a failure from the first connection attempt into something actionable.
 *
 * The previous behaviour showed the same sentence for every cause, so a user
 * whose local service had stopped and a user whose app and service disagreed
 * about protocol were told the same thing. Only recognisable causes are
 * classified; anything else stays `unknown` rather than guessing, because a
 * confident wrong instruction is worse than a generic one.
 */
export function connectionFailureGuidance(error: unknown): ConnectionFailureGuidance {
  if (isServiceVersionMismatch(error)) {
    return {
      reason: 'version-mismatch',
      message: 'Context Relay and its local service are different versions.',
      steps: ['Close Context Relay completely.', 'Run the latest installer.', 'Reopen Context Relay.'],
      retryable: false,
    };
  }

  const code = errorCode(error);
  if (code && NOT_RUNNING_CODES.has(code)) {
    return {
      reason: 'service-not-running',
      message: 'The local workspace service is not running.',
      steps: ['Open Context Relay again to start it.', 'If it does not start, restart your computer and retry.'],
      retryable: true,
    };
  }
  if (code && UNREACHABLE_CODES.has(code)) {
    return {
      reason: 'service-unreachable',
      message: 'Context Relay could not reach the local workspace service.',
      steps: [
        'Check that no other app is using the same local workspace.',
        'Allow Context Relay through your firewall or antivirus, then retry.',
      ],
      retryable: true,
    };
  }

  const text = describe(error);
  if (NOT_RUNNING.test(text)) {
    return {
      reason: 'service-not-running',
      message: 'The local workspace service is not running.',
      steps: ['Open Context Relay again to start it.', 'If it does not start, restart your computer and retry.'],
      retryable: true,
    };
  }
  if (UNREACHABLE.test(text)) {
    return {
      reason: 'service-unreachable',
      message: 'Context Relay could not reach the local workspace service.',
      steps: [
        'Check that no other app is using the same local workspace.',
        'Allow Context Relay through your firewall or antivirus, then retry.',
      ],
      retryable: true,
    };
  }
  return {
    reason: 'unknown',
    message: 'Could not connect to the local workspace.',
    steps: ['Retry the connection.'],
    retryable: true,
  };
}

function errorCode(error: unknown): string {
  if (!error || typeof error !== 'object') return '';
  const code = (error as Record<string, unknown>).code;
  return typeof code === 'string' ? code : '';
}

function describe(error: unknown): string {
  if (typeof error === 'string') return error;
  if (!error || typeof error !== 'object') return '';
  const parts: string[] = [];
  for (const key of ['message', 'code', 'reason', 'detail'] as const) {
    const value = (error as Record<string, unknown>)[key];
    if (typeof value === 'string') parts.push(value);
  }
  return parts.join(' ');
}
