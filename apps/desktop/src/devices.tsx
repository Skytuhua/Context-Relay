import { type FormEvent, useCallback, useEffect, useRef, useState } from 'react';

import type {
  ClientError,
  DeviceSummary,
  PairingApprovalInfo,
  PairingCode,
  PairingId,
  PairingInviteInfo,
  PairingRequestInfo,
  PairingSafetyNumber,
  RecoveryEnrollmentChallenge,
  RecoveryEnrollmentConfirmParams,
  RecoveryEnrollmentId,
  RecoveryEnrollmentStatus,
} from './bindings';
import type { DeviceGateway, PairingStatusResult } from './workspace';

const PAIRING_CODE_PATTERN = /^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/;
const SAFETY_NUMBER_PATTERN = /^[0-9A-F]{4}(?:-[0-9A-F]{4}){4}$/;
const HOSTED_PAIRING_UNAVAILABLE =
  'Pairing needs the hosted device service and is not available in this build.';
const HOSTED_RECOVERY_UNAVAILABLE =
  'Recovery setup needs the hosted workspace service and is not available in this build.';

type PairingRole = 'approver' | 'joiner';

export function DevicesScreen({
  gateway,
  pollIntervalMs = 1_000,
}: {
  gateway: DeviceGateway;
  pollIntervalMs?: number;
}) {
  const [devices, setDevices] = useState<DeviceSummary[]>([]);
  const [pairingId, setPairingId] = useState<PairingId | null>(null);
  const [role, setRole] = useState<PairingRole | null>(null);
  const [invite, setInvite] = useState<PairingInviteInfo | null>(null);
  const [reviewRequest, setReviewRequest] = useState<PairingRequestInfo | null>(null);
  const [approval, setApproval] = useState<PairingApprovalInfo | null>(null);
  const [rejected, setRejected] = useState(false);
  const [awaitingConfirmation, setAwaitingConfirmation] = useState(false);
  const [polling, setPolling] = useState(false);
  const [working, setWorking] = useState(false);
  const [pairingUnavailable, setPairingUnavailable] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const reviewDialogRef = useRef<HTMLDialogElement>(null);
  const reviewTriggerRef = useRef<HTMLButtonElement>(null);

  const loadDevices = useCallback(async () => {
    try {
      setDevices(await gateway.devices());
    } catch {
      setError('Trusted devices could not be loaded.');
    }
  }, [gateway]);

  useEffect(() => {
    void loadDevices();
  }, [loadDevices]);

  useEffect(() => {
    if (!invite) return;
    setNowMs(Date.now());
    const timer = setInterval(() => setNowMs(Date.now()), 1_000);
    return () => clearInterval(timer);
  }, [invite]);

  const applyStatus = useCallback(
    async (result: PairingStatusResult, currentRole: PairingRole | null) => {
      const invalidForRole = () => {
        setPairingId(null);
        setRole(null);
        setInvite(null);
        setReviewRequest(null);
        setApproval(null);
        setRejected(false);
        setAwaitingConfirmation(false);
        setError('Pairing status was not valid for this device.');
        return false;
      };

      switch (result.kind) {
        case 'pairing_invite_status':
          if (currentRole !== 'approver') return invalidForRole();
          if (result.data.status === 'canceled') {
            setPairingId(null);
            setRole(null);
            setInvite(null);
            setMessage('Pairing canceled.');
            return false;
          }
          if (result.data.status === 'rejected') {
            setPairingId(null);
            setRole(null);
            setInvite(null);
            setRejected(true);
            setMessage('Pairing request rejected.');
            return false;
          }
          return result.data.status === 'pending';
        case 'pairing_request':
          if (result.data.status === 'rejected') {
            setPairingId(null);
            setRole(null);
            setInvite(null);
            if (currentRole === 'approver') setRejected(true);
            else setReviewRequest(null);
            setAwaitingConfirmation(false);
            setMessage('Pairing request rejected.');
            return false;
          }
          if (result.data.status === 'canceled') {
            setPairingId(null);
            setRole(null);
            setInvite(null);
            setReviewRequest(null);
            setAwaitingConfirmation(false);
            setMessage('Pairing canceled.');
            return false;
          }
          if (currentRole === 'approver' && result.data.status === 'pending') {
            setInvite(null);
            setRejected(false);
            setReviewRequest(result.data.request);
            setMessage('A device is waiting for review.');
            return false;
          }
          if (currentRole === 'joiner' && result.data.status === 'approved') {
            setAwaitingConfirmation(true);
            setMessage('Approval received. Enter the safety number shown on the trusted device.');
            return false;
          }
          if (currentRole !== 'joiner' && currentRole !== 'approver') return invalidForRole();
          if (result.data.status === 'approved') return invalidForRole();
          setMessage('Waiting for approval on the trusted device.');
          return true;
        case 'pairing_approval':
          if (currentRole !== 'approver') return invalidForRole();
          setInvite(null);
          setRejected(false);
          setApproval(result.data.approval);
          setMessage('Compare all five groups on the joining device.');
          return false;
        case 'pairing_completion':
          if (currentRole !== 'joiner') return invalidForRole();
          setPairingId(null);
          setRole(null);
          setAwaitingConfirmation(false);
          setMessage('This device is now trusted.');
          await loadDevices();
          return false;
      }
    },
    [loadDevices],
  );

  useEffect(() => {
    if (!pairingId || !polling) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const poll = async () => {
      try {
        const result = await gateway.pairingStatus(pairingId);
        if (stopped) return;
        const shouldContinue = await applyStatus(result, role);
        if (shouldContinue && !stopped) timer = setTimeout(poll, pollIntervalMs);
        else setPolling(false);
      } catch (cause) {
        if (!stopped) {
          setError(safePairingError(cause, 'Pairing status could not be refreshed.'));
          setPolling(false);
        }
      }
    };

    timer = setTimeout(poll, pollIntervalMs);
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  }, [applyStatus, gateway, pairingId, pollIntervalMs, polling, role]);

  async function createInvite() {
    setWorking(true);
    setError(null);
    setMessage(null);
    setApproval(null);
    setRejected(false);
    setAwaitingConfirmation(false);
    try {
      const result = await gateway.createPairingInvite();
      setInvite(result.data.invite);
      setPairingId(result.data.invite.pairingId);
      setRole('approver');
      setPolling(true);
      setMessage('Share this one-time code with the device you want to trust.');
    } catch (cause) {
      if (isClientError(cause, 'harness_unsupported')) setPairingUnavailable(true);
      setError(safePairingError(cause, 'A pairing code could not be created.'));
    } finally {
      setWorking(false);
    }
  }

  async function joinPairing(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const nextCode = String(data.get('code') ?? '').trim().toUpperCase();
    const deviceName = String(data.get('deviceName') ?? '').trim();
    if (!PAIRING_CODE_PATTERN.test(nextCode) || !deviceName) {
      setError('Enter the complete pairing code and this device name.');
      return;
    }

    setWorking(true);
    setError(null);
    setMessage(null);
    setApproval(null);
    setRejected(false);
    setAwaitingConfirmation(false);
    try {
      const result = await gateway.joinPairing(nextCode as PairingCode, deviceName);
      setPairingId(result.data.request.pairingId);
      setRole('joiner');
      setInvite(null);
      setPolling(true);
      setMessage('Waiting for approval on the trusted device.');
    } catch (cause) {
      if (isClientError(cause, 'harness_unsupported')) setPairingUnavailable(true);
      setError(safePairingError(cause, 'The pairing request could not be submitted.'));
    } finally {
      setWorking(false);
    }
  }

  function openReview(trigger: HTMLButtonElement) {
    reviewTriggerRef.current = trigger;
    reviewDialogRef.current?.showModal();
  }

  function resetPairingView(nextMessage: string) {
    setPairingId(null);
    setRole(null);
    setInvite(null);
    setReviewRequest(null);
    setApproval(null);
    setRejected(false);
    setAwaitingConfirmation(false);
    setPolling(false);
    setError(null);
    setMessage(nextMessage);
  }

  async function decide(approve: boolean) {
    if (!reviewRequest) return;
    setWorking(true);
    setError(null);
    try {
      const latest = await gateway.pairingStatus(reviewRequest.pairingId);
      if (
        latest.kind !== 'pairing_request' ||
        latest.data.status !== 'pending' ||
        latest.data.request.requestDigest !== reviewRequest.requestDigest
      ) {
        if (latest.kind === 'pairing_request') setReviewRequest(latest.data.request);
        setRejected(false);
        reviewDialogRef.current?.close();
        setError('The pairing request changed. Review it again.');
        return;
      }

      const result = await gateway.decidePairing(
        reviewRequest.pairingId,
        reviewRequest.requestDigest,
        approve,
      );
      reviewDialogRef.current?.close();
      if (result.kind === 'pairing_approval') {
        setInvite(null);
        setRejected(false);
        setApproval(result.data.approval);
        setMessage('Compare all five groups on the joining device.');
      } else {
        setInvite(null);
        setPairingId(null);
        setRole(null);
        setRejected(true);
        setMessage('Pairing request rejected.');
      }
    } catch (cause) {
      reviewDialogRef.current?.close();
      setError(safePairingError(cause, 'The pairing decision could not be saved.'));
    } finally {
      setWorking(false);
    }
  }

  async function confirmSafetyNumber(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!pairingId) return;
    const safetyNumber = String(new FormData(event.currentTarget).get('safetyNumber') ?? '')
      .trim()
      .toUpperCase();
    if (!SAFETY_NUMBER_PATTERN.test(safetyNumber)) {
      setError('Enter all five safety-number groups.');
      return;
    }

    setWorking(true);
    setError(null);
    try {
      const result = await gateway.confirmPairing(
        pairingId,
        safetyNumber as PairingSafetyNumber,
      );
      await applyStatus(result, role);
    } catch (cause) {
      setError(
        isClientError(cause, 'conflict') || isClientError(cause, 'invalid_request')
          ? 'The safety number did not match. Check all five groups.'
          : safePairingError(cause, 'Pairing could not be completed.'),
      );
    } finally {
      setWorking(false);
    }
  }

  async function cancelPairing() {
    if (!pairingId) return;
    setWorking(true);
    setError(null);
    try {
      await gateway.cancelPairing(pairingId);
      setPairingId(null);
      setRole(null);
      setPolling(false);
      setInvite(null);
      setReviewRequest(null);
      setApproval(null);
      setRejected(false);
      setAwaitingConfirmation(false);
      setMessage('Pairing canceled.');
    } catch (cause) {
      setError(safePairingError(cause, 'Pairing could not be canceled.'));
    } finally {
      setWorking(false);
    }
  }

  return (
    <section className="screen-content devices-screen" aria-labelledby="trusted-devices-title">
      <section className="trusted-devices" aria-labelledby="trusted-devices-title">
        <h2 id="trusted-devices-title">Trusted devices</h2>
        {devices.length === 0 ? (
          <p>No trusted devices were found.</p>
        ) : (
          <ul className="device-list">
            {devices.map((device) => (
              <li className="device-row" key={device.deviceId}>
                <div>
                  <h3>{device.name}</h3>
                  <p className="device-meta">
                    {platformName(device.platform)} · {device.state === 'active' ? 'Trusted' : 'Revoked'}
                  </p>
                </div>
                {device.isCurrent && <span className="device-tag">Current device</span>}
              </li>
            ))}
          </ul>
        )}
      </section>

      <RecoveryEnrollmentPanel
        gateway={gateway}
        onComplete={loadDevices}
        pollIntervalMs={pollIntervalMs}
      />

      <section className="pairing-workspace" aria-labelledby="pair-device-title">
        <div>
          <h2 id="pair-device-title">Pair another device</h2>
          <p>
            The short code only finds the request. Trust is added after both devices compare the
            full safety number.
          </p>
        </div>

        {!pairingUnavailable && !pairingId && (
          <div className="pairing-actions">
            <div>
              <h3>Use this trusted device</h3>
              <p>Create a one-time code for the device you are adding.</p>
              <button
                className="primary-action"
                disabled={working}
                onClick={() => void createInvite()}
                type="button"
              >
                Create pairing code
              </button>
            </div>
            <form aria-label="Join a device" className="capture-form compact-form" onSubmit={joinPairing}>
              <h3>Trust this device</h3>
              <p>Enter the one-time code shown by a trusted device.</p>
              <label className="field">
                <span>Pairing code</span>
                <input
                  autoComplete="off"
                  inputMode="text"
                  maxLength={11}
                  name="code"
                  placeholder="01234-ABCDE"
                  required
                  type="text"
                />
              </label>
              <label className="field">
                <span>Device name</span>
                <input autoComplete="off" maxLength={256} name="deviceName" required type="text" />
              </label>
              <button className="secondary-action" disabled={working} type="submit">
                Request approval
              </button>
            </form>
          </div>
        )}

        {invite && pairingId && (
          <div className="pairing-step">
            <h3>One-time pairing code</h3>
            <code className="pairing-code">{invite.code}</code>
            <p>
              Expires {formatTimestamp(invite.expiresAt)} · {formatRemaining(invite.expiresAt, nowMs)} remaining
            </p>
            <button
              className="secondary-action"
              disabled={working}
              onClick={() => void cancelPairing()}
              type="button"
            >
              Cancel pairing
            </button>
          </div>
        )}

        {reviewRequest && (
          <div className="pairing-step">
            <h3>{approval ? 'Approved request' : rejected ? 'Rejected request' : 'Approval required'}</h3>
            <p>
              {approval
                ? `${reviewRequest.deviceName} was approved after an exact review.`
                : rejected
                  ? `${reviewRequest.deviceName} was rejected after an exact review.`
                  : `${reviewRequest.deviceName} is waiting for an exact review.`}
            </p>
            <button
              className="primary-action"
              onClick={(event) => openReview(event.currentTarget)}
              type="button"
            >
              Review pairing request
            </button>
          </div>
        )}

        {approval && (
          <div className="pairing-step">
            <h3>Compare the full safety number</h3>
            <p>Read all five groups to the person using {approval.request.deviceName}.</p>
            <code className="pairing-safety">{approval.safetyNumber}</code>
            <button
              className="secondary-action"
              onClick={() => resetPairingView('Pairing review finished.')}
              type="button"
            >
              Done comparing
            </button>
          </div>
        )}

        {awaitingConfirmation && pairingId && (
          <form
            aria-label="Confirm safety number"
            className="capture-form pairing-step"
            onSubmit={confirmSafetyNumber}
          >
            <h3>Confirm the safety number</h3>
            <p>Enter all five groups exactly as shown on the trusted device.</p>
            <label className="field">
              <span>Safety number</span>
              <input
                autoComplete="off"
                maxLength={24}
                name="safetyNumber"
                placeholder="0123-4567-89AB-CDEF-0123"
                required
                type="text"
              />
            </label>
            <button className="primary-action" disabled={working} type="submit">
              Trust this device
            </button>
          </form>
        )}

        {role === 'joiner' && pairingId && !awaitingConfirmation && (
          <button
            className="secondary-action"
            onClick={() =>
              resetPairingView(
                'Stopped checking this pairing. It can still be approved before expiry, but this device will not trust it without confirmation.',
              )
            }
            type="button"
          >
            Stop checking
          </button>
        )}

        {pairingId && !polling && !reviewRequest && !approval && !awaitingConfirmation && !rejected && (
          <button
            className="secondary-action"
            onClick={() => {
              setError(null);
              setPolling(true);
            }}
            type="button"
          >
            Retry pairing status
          </button>
        )}

        {error && <p className="form-error" role="alert">{error}</p>}
        {message && <p className="pairing-status" role="status" aria-live="polite">{message}</p>}
      </section>

      <dialog
        aria-labelledby="pairing-review-title"
        onClose={() => reviewTriggerRef.current?.focus()}
        ref={reviewDialogRef}
      >
        <h2 id="pairing-review-title">Approve new device</h2>
        {reviewRequest && (
          <dl className="security-facts pairing-review">
            <div>
              <dt>Device</dt>
              <dd>{reviewRequest.deviceName}</dd>
            </div>
            <div>
              <dt>Platform</dt>
              <dd>{platformName(reviewRequest.platform)}</dd>
            </div>
            <div>
              <dt>Requested</dt>
              <dd>{formatTimestamp(reviewRequest.requestedAt)}</dd>
            </div>
            <div>
              <dt>Key fingerprint</dt>
              <dd><code>{reviewRequest.keyFingerprint}</code></dd>
            </div>
            <div>
              <dt>Request digest</dt>
              <dd><code>{reviewRequest.requestDigest}</code></dd>
            </div>
          </dl>
        )}
        <div className="pairing-dialog-actions">
          {!approval && !rejected && (
            <>
              <button
                className="primary-action"
                disabled={working}
                onClick={() => void decide(true)}
                type="button"
              >
                Approve device
              </button>
              <button
                className="secondary-action"
                disabled={working}
                onClick={() => void decide(false)}
                type="button"
              >
                Reject device
              </button>
            </>
          )}
          <button
            className="secondary-action"
            onClick={() => reviewDialogRef.current?.close()}
            type="button"
          >
            Close review
          </button>
        </div>
      </dialog>
    </section>
  );
}

function RecoveryEnrollmentPanel({
  gateway,
  onComplete,
  pollIntervalMs,
}: {
  gateway: DeviceGateway;
  onComplete: () => Promise<void>;
  pollIntervalMs: number;
}) {
  const [status, setStatus] = useState<RecoveryEnrollmentStatus | null>(null);
  const [challenge, setChallenge] = useState<RecoveryEnrollmentChallenge | null>(null);
  const [confirmations, setConfirmations] = useState<string[]>([]);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [working, setWorking] = useState(false);
  const [unavailable, setUnavailable] = useState(false);
  const [lostChallengeCleanupFailed, setLostChallengeCleanupFailed] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mountedRef = useRef(true);
  const challengeRef = useRef<RecoveryEnrollmentChallenge | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);

  const clearChallenge = useCallback(() => {
    challengeRef.current = null;
    setChallenge(null);
    setConfirmations([]);
  }, []);

  const applyRecoveryStatus = useCallback(
    async (nextStatus: RecoveryEnrollmentStatus) => {
      if (!mountedRef.current) return;
      setStatus(nextStatus);
      switch (nextStatus.state) {
        case 'idle':
          setLostChallengeCleanupFailed(false);
          setMessage(null);
          setError(null);
          return;
        case 'awaiting_confirmation':
          setLostChallengeCleanupFailed(false);
          clearChallenge();
          if (nextStatus.enrollmentId) {
            try {
              await gateway.recoveryEnrollmentCancel(nextStatus.enrollmentId);
              if (!mountedRef.current) return;
              setStatus(idleRecoveryStatus());
              setError(null);
              setMessage('The previous recovery phrase is no longer valid. Start setup again.');
            } catch {
              try {
                const refreshed = await gateway.recoveryEnrollmentOverview();
                if (!mountedRef.current) return;
                if (refreshed.state === 'idle' && refreshed.enrollmentId === null) {
                  setStatus(refreshed);
                  setError(null);
                  setMessage('The previous recovery phrase is no longer valid. Start setup again.');
                  return;
                }
                if (refreshed.state !== 'awaiting_confirmation') {
                  await applyRecoveryStatus(refreshed);
                  return;
                }
                setStatus(refreshed);
              } catch {
                if (!mountedRef.current) return;
              }
              setLostChallengeCleanupFailed(true);
              setError('The previous recovery setup could not be canceled. Try again.');
            }
          } else {
            setError('Recovery setup returned an incomplete status.');
          }
          return;
        case 'submitting':
          setLostChallengeCleanupFailed(false);
          clearChallenge();
          setError(null);
          setMessage('Recovery setup is being secured.');
          return;
        case 'complete':
          setLostChallengeCleanupFailed(false);
          clearChallenge();
          setError(null);
          setMessage('Recovery is ready.');
          await onComplete();
          if (mountedRef.current) queueMicrotask(() => headingRef.current?.focus());
          return;
        case 'conflict':
          setLostChallengeCleanupFailed(false);
          clearChallenge();
          setMessage(null);
          setError(
            'Recovery setup conflicts with the hosted workspace. Contact support before trying again.',
          );
      }
    },
    [clearChallenge, gateway, onComplete],
  );

  useEffect(() => {
    mountedRef.current = true;
    void gateway
      .recoveryEnrollmentOverview()
      .then((nextStatus) => {
        if (mountedRef.current) void applyRecoveryStatus(nextStatus);
      })
      .catch((cause) => {
        if (!mountedRef.current) return;
        if (isClientError(cause, 'harness_unsupported')) {
          setUnavailable(true);
          setStatus(null);
          setError(null);
        } else {
          setError('Recovery status could not be loaded.');
        }
      });

    return () => {
      mountedRef.current = false;
      const activeChallenge = challengeRef.current;
      challengeRef.current = null;
      if (activeChallenge) {
        void gateway.recoveryEnrollmentCancel(activeChallenge.enrollmentId).catch(() => undefined);
      }
    };
  }, [applyRecoveryStatus, gateway]);

  useEffect(() => {
    if (!challenge) return;
    setNowMs(Date.now());
    const timer = setInterval(() => setNowMs(Date.now()), 1_000);
    return () => clearInterval(timer);
  }, [challenge]);

  useEffect(() => {
    if (!challenge || Number(challenge.expiresAtMs) > nowMs) return;
    const expired = challenge;
    clearChallenge();
    setStatus(idleRecoveryStatus());
    setMessage(null);
    setError('Recovery setup expired. Start again with a new phrase.');
    void gateway.recoveryEnrollmentCancel(expired.enrollmentId).catch(() => undefined);
  }, [challenge, clearChallenge, gateway, nowMs]);

  useEffect(() => {
    if (status?.state !== 'submitting' || !status.enrollmentId) return;
    let stopped = false;
    const timer = setTimeout(() => {
      void gateway
        .recoveryEnrollmentStatus(status.enrollmentId as RecoveryEnrollmentId)
        .then((nextStatus) => {
          if (!stopped) void applyRecoveryStatus(nextStatus);
        })
        .catch(() => {
          if (!stopped) setError('Recovery status could not be refreshed.');
        });
    }, pollIntervalMs);
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [applyRecoveryStatus, gateway, pollIntervalMs, status]);

  async function beginRecovery() {
    setWorking(true);
    setError(null);
    setMessage(null);
    try {
      const result = await gateway.recoveryEnrollmentBegin();
      if (!mountedRef.current) {
        if (result.kind === 'challenge') {
          void gateway.recoveryEnrollmentCancel(result.data.enrollmentId).catch(() => undefined);
        }
        return;
      }
      if (result.kind === 'status') {
        await applyRecoveryStatus(result.data);
        return;
      }
      if (!validChallenge(result.data)) {
        setError('Recovery setup returned an invalid challenge.');
        return;
      }
      challengeRef.current = result.data;
      setChallenge(result.data);
      setConfirmations(result.data.confirmationPositions.map(() => ''));
      setStatus({
        enrollmentId: result.data.enrollmentId,
        state: 'awaiting_confirmation',
        createdAtMs: result.data.createdAtMs,
        transitionedAtMs: result.data.createdAtMs,
      });
      setNowMs(Date.now());
      setMessage('Enter the four requested words from the phrase you saved.');
    } catch (cause) {
      if (!mountedRef.current) return;
      if (isClientError(cause, 'harness_unsupported')) {
        setUnavailable(true);
        setError(null);
        return;
      }
      setError(safeRecoveryError(cause, 'Recovery setup could not begin.'));
    } finally {
      if (mountedRef.current) setWorking(false);
    }
  }

  async function retryLostChallengeCleanup() {
    if (status?.state !== 'awaiting_confirmation' || !status.enrollmentId) return;
    setWorking(true);
    setError(null);
    try {
      await applyRecoveryStatus(status);
    } finally {
      if (mountedRef.current) setWorking(false);
    }
  }

  async function confirmRecovery(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!challenge) return;
    const nextConfirmations = confirmations.map((word) => word.trim());
    if (nextConfirmations.some((word) => !word)) {
      setError('Enter all four requested recovery words.');
      return;
    }
    const params: RecoveryEnrollmentConfirmParams = {
      enrollmentId: challenge.enrollmentId,
      confirmations: challenge.confirmationPositions.map((position, index) => ({
        position,
        word: nextConfirmations[index],
      })),
    };
    setWorking(true);
    setError(null);
    try {
      const result = await gateway.recoveryEnrollmentConfirm(params);
      if (!mountedRef.current) return;
      if (result.kind === 'canceled') {
        setMessage('Recovery confirmation was canceled. Your four entries are still here.');
      } else if (result.kind === 'complete') {
        clearChallenge();
        await applyRecoveryStatus({
          enrollmentId: result.data.enrollmentId,
          state: 'complete',
          createdAtMs: status?.createdAtMs ?? null,
          transitionedAtMs: status?.transitionedAtMs ?? null,
        });
      } else {
        clearChallenge();
        await applyRecoveryStatus(result.data);
      }
    } catch (cause) {
      if (!mountedRef.current) return;
      clearChallenge();
      setStatus(idleRecoveryStatus());
      setMessage(null);
      setError(safeRecoveryError(cause, 'Recovery confirmation failed. Start setup again.'));
    } finally {
      if (mountedRef.current) setWorking(false);
    }
  }

  async function cancelRecovery() {
    if (!challenge) return;
    setWorking(true);
    setError(null);
    try {
      await gateway.recoveryEnrollmentCancel(challenge.enrollmentId);
      if (!mountedRef.current) return;
      clearChallenge();
      setStatus(idleRecoveryStatus());
      setMessage('Recovery setup canceled. The previous phrase is no longer valid.');
    } catch {
      if (mountedRef.current) setError('Recovery setup could not be canceled. Try again.');
    } finally {
      if (mountedRef.current) setWorking(false);
    }
  }

  return (
    <section className="recovery-workspace" aria-labelledby="recovery-title">
      <div>
        <h2 id="recovery-title" ref={headingRef} tabIndex={-1}>Recovery</h2>
        <p>
          Create a one-time recovery phrase for restoring access if every trusted device is lost.
        </p>
      </div>

      {unavailable && <p>{HOSTED_RECOVERY_UNAVAILABLE}</p>}

      {!unavailable && status?.state === 'idle' && !challenge && (
        <button
          className="primary-action"
          disabled={working}
          onClick={() => void beginRecovery()}
          type="button"
        >
          Set up recovery
        </button>
      )}

      {lostChallengeCleanupFailed && status?.state === 'awaiting_confirmation' && (
        <button
          className="secondary-action"
          disabled={working}
          onClick={() => void retryLostChallengeCleanup()}
          type="button"
        >
          Retry recovery cleanup
        </button>
      )}

      {challenge && (
        <form
          aria-label="Confirm recovery phrase"
          className="capture-form recovery-challenge"
          onSubmit={confirmRecovery}
        >
          <h3>Confirm your saved phrase</h3>
          <p>
            {formatRemaining(challenge.expiresAtMs, nowMs)} remaining. Enter these words exactly as
            written in the native recovery window.
          </p>
          <div className="recovery-word-grid">
            {challenge.confirmationPositions.map((position, index) => (
              <label className="field" key={position}>
                <span>Word {position}</span>
                <input
                  aria-label={`Word ${position}`}
                  autoComplete="off"
                  maxLength={64}
                  name={`word-${position}`}
                  onChange={(event) => {
                    const value = event.currentTarget.value;
                    setConfirmations((current) =>
                      current.map((word, wordIndex) => (wordIndex === index ? value : word)),
                    );
                  }}
                  required
                  spellCheck={false}
                  type="text"
                  value={confirmations[index] ?? ''}
                />
              </label>
            ))}
          </div>
          <div className="recovery-actions">
            <button className="primary-action" disabled={working} type="submit">
              Confirm recovery
            </button>
            <button
              className="secondary-action"
              disabled={working}
              onClick={() => void cancelRecovery()}
              type="button"
            >
              Cancel recovery setup
            </button>
          </div>
        </form>
      )}

      {error && <p className="form-error" role="alert">{error}</p>}
      {message && <p className="recovery-status" role="status" aria-live="polite">{message}</p>}
    </section>
  );
}

function idleRecoveryStatus(): RecoveryEnrollmentStatus {
  return {
    enrollmentId: null,
    state: 'idle',
    createdAtMs: null,
    transitionedAtMs: null,
  };
}

function validChallenge(challenge: RecoveryEnrollmentChallenge) {
  const positions = challenge.confirmationPositions;
  return (
    positions.length === 4 &&
    positions.every((position) => Number.isInteger(position) && position >= 1 && position <= 24) &&
    new Set(positions).size === positions.length &&
    positions.every((position, index) => index === 0 || positions[index - 1] < position) &&
    Number(challenge.expiresAtMs) > Number(challenge.createdAtMs)
  );
}

function platformName(platform: DeviceSummary['platform']) {
  return platform === 'macos' ? 'macOS' : 'Windows';
}

function formatTimestamp(timestamp: string) {
  const milliseconds = Number(timestamp);
  return Number.isFinite(milliseconds) ? new Date(milliseconds).toLocaleString() : timestamp;
}

function formatRemaining(timestamp: string, nowMs: number) {
  const remainingMs = Math.max(0, Number(timestamp) - nowMs);
  const remainingSeconds = Math.ceil(remainingMs / 1_000);
  if (remainingSeconds < 60) return `${remainingSeconds} seconds`;
  return `${Math.ceil(remainingSeconds / 60)} minutes`;
}

function isClientError(cause: unknown, code: ClientError['code']): cause is ClientError {
  return (
    typeof cause === 'object' &&
    cause !== null &&
    'code' in cause &&
    (cause as { code?: unknown }).code === code
  );
}

function safePairingError(cause: unknown, fallback: string) {
  if (isClientError(cause, 'harness_unsupported')) return HOSTED_PAIRING_UNAVAILABLE;
  if (isClientError(cause, 'canceled')) return 'Pairing was canceled.';
  if (isClientError(cause, 'timeout') || isClientError(cause, 'busy')) {
    return 'Pairing is temporarily unavailable. Try again.';
  }
  return fallback;
}

function safeRecoveryError(cause: unknown, fallback: string) {
  if (isClientError(cause, 'harness_unsupported')) return HOSTED_RECOVERY_UNAVAILABLE;
  if (isClientError(cause, 'canceled')) return 'Recovery setup was canceled.';
  if (isClientError(cause, 'conflict')) {
    return 'The recovery words did not match. Start setup again with a new phrase.';
  }
  if (isClientError(cause, 'timeout') || isClientError(cause, 'busy')) {
    return 'Recovery setup is temporarily unavailable. Try again.';
  }
  return fallback;
}
