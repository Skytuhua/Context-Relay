import { describe, expect, it } from 'vitest';

import { connectionFailureGuidance, isServiceVersionMismatch } from './service-error';

describe('connectionFailureGuidance', () => {
  it('separates a version mismatch from every other cause', () => {
    const guidance = connectionFailureGuidance({ code: 'protocol_version_unsupported' });
    expect(guidance.reason).toBe('version-mismatch');
    // Retrying cannot fix a version disagreement, so the retry affordance would lie.
    expect(guidance.retryable).toBe(false);
    expect(guidance.steps).toContain('Run the latest installer.');
  });

  it('tells a stopped service apart from an unreachable one', () => {
    expect(connectionFailureGuidance(new Error('daemon is not running')).reason).toBe('service-not-running');
    expect(connectionFailureGuidance(new Error('connect failed: broken pipe')).reason).toBe('service-unreachable');
  });

  it('reads a cause from code, reason or detail, not just message', () => {
    expect(connectionFailureGuidance({ code: 'service_not_running' }).reason).toBe('service-not-running');
    expect(connectionFailureGuidance({ reason: 'the local service is not running' }).reason).toBe('service-not-running');
    expect(connectionFailureGuidance({ detail: 'socket connect timed out' }).reason).toBe('service-unreachable');
    expect(connectionFailureGuidance('service not running').reason).toBe('service-not-running');
  });

  it('classifies the error the Tauri layer actually returns when the service is down', () => {
    // safe_ipc_error in main.rs maps every non-version IPC failure, including
    // EndpointNotFound, to code Internal with this exact message. It is the most
    // common connection failure there is, so it must not fall through to unknown.
    const actual = { code: 'internal', message: 'The local service is unavailable' };
    expect(connectionFailureGuidance(actual).reason).toBe('service-not-running');
    expect(connectionFailureGuidance(new Error('The local service is unavailable')).reason).toBe(
      'service-not-running',
    );
  });

  it('classifies the protocol ErrorCode set without relying on message wording', () => {
    // These arrive as structured codes from the daemon, not English sentences.
    expect(connectionFailureGuidance({ code: 'daemon_not_running' }).reason).toBe('service-not-running');
    expect(connectionFailureGuidance({ code: 'timeout' }).reason).toBe('service-unreachable');
    expect(connectionFailureGuidance({ code: 'busy' }).reason).toBe('service-unreachable');
    // A code with no bearing on connectivity must not be forced into a bucket.
    expect(connectionFailureGuidance({ code: 'vault_locked', message: 'vault locked' }).reason).toBe('unknown');
    expect(connectionFailureGuidance({ code: 'internal' }).reason).toBe('unknown');
  });

  it('falls back rather than guessing at an unrecognised cause', () => {
    for (const failure of [new Error('kaboom'), { code: 42 }, null, undefined, 7]) {
      const guidance = connectionFailureGuidance(failure);
      expect(guidance.reason).toBe('unknown');
      expect(guidance.steps).toEqual(['Retry the connection.']);
      expect(guidance.retryable).toBe(true);
    }
  });

  it('gives every classified cause a distinct, actionable message', () => {
    const reasons = ['version-mismatch', 'service-not-running', 'service-unreachable', 'unknown'] as const;
    const messages = reasons.map((input) => {
      const failure = {
        'version-mismatch': { code: 'protocol_version_unsupported' },
        'service-not-running': new Error('daemon is not running'),
        'service-unreachable': new Error('connect failed'),
        unknown: new Error('kaboom'),
      }[input];
      return connectionFailureGuidance(failure).message;
    });
    expect(new Set(messages).size).toBe(reasons.length);
    for (const message of messages) expect(message).not.toMatch(/\b(undefined|null|NaN|Error)\b/);
  });
});

describe('isServiceVersionMismatch', () => {
  it('ignores values that merely look like the code', () => {
    expect(isServiceVersionMismatch({ code: 'something_else' })).toBe(false);
    expect(isServiceVersionMismatch({ code: 'PROTOCOL_VERSION_UNSUPPORTED' })).toBe(false);
    expect(isServiceVersionMismatch({ code: 1 })).toBe(false);
    expect(isServiceVersionMismatch('protocol_version_unsupported')).toBe(false);
    expect(isServiceVersionMismatch(null)).toBe(false);
  });
});
