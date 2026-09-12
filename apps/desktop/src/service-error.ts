export const SERVICE_UPDATE_GUIDANCE = 'Context Relay and its local service use different versions. Close Context Relay, run the latest installer, then reopen it.';

export function isServiceVersionMismatch(error: unknown): boolean {
  return !!error && typeof error === 'object' && 'code' in error && error.code === 'protocol_version_unsupported';
}
