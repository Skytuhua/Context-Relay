import type { HarnessPrepareParams, HarnessPreparationStatus, HarnessExecutionParams, HarnessExecutionStatus, HarnessSetupRecord, HarnessSetupsPage, HarnessParams, PlanId, ProbeReport, SetupPlan } from './bindings';
import * as protocolValidation from './protocol-validation';

const assertSetupPlan: (value: unknown) => asserts value is SetupPlan = protocolValidation.assertSetupPlan;
const assertProbeReport: (value: unknown) => asserts value is ProbeReport = protocolValidation.assertProbeReport;

export interface HarnessGateway {
  harnessPrepare(params: HarnessPrepareParams): Promise<HarnessPreparationStatus>;
  harnessPreparationStatus(params: HarnessPrepareParams): Promise<HarnessPreparationStatus>;
  harnessPreparationCancel(params: HarnessPrepareParams): Promise<HarnessPreparationStatus>;
  harnessPreparedPreview(params: HarnessPrepareParams): Promise<SetupPlan>;
  harnessExecutionStart(params: HarnessExecutionParams): Promise<HarnessExecutionStatus>;
  harnessExecutionStatus(params: HarnessExecutionParams): Promise<HarnessExecutionStatus>;
  harnessExecutionCurrent(): Promise<HarnessExecutionStatus | null>;
  harnessSetupGet(planId: PlanId): Promise<HarnessSetupRecord>;
  harnessSetupsList(after?: PlanId | null): Promise<HarnessSetupsPage>;
  harnessProbe(params: HarnessParams): Promise<ProbeReport>;
  harnessPreview(params: HarnessParams): Promise<SetupPlan>;
  harnessApply(planId: PlanId): Promise<void>;
  harnessRollback(planId: PlanId): Promise<void>;
}

export function validateHarnessProbe(value: unknown, params: HarnessParams): ProbeReport {
  assertProbeReport(value);
  if ((value.codexSavedHookApproval !== null && (params.harness !== 'codex' || value.harnessVersion !== '0.144.6')) ||
    value.activeProfile !== params.hermesProfile ||
    (value.capability === 'full' && (!value.executable || !value.executableSha256 || !value.harnessVersion))) {
    throw new Error('Harness discovery does not match the selection.');
  }
  return value;
}

export function validateHarnessPlan(value: unknown, params: HarnessParams): SetupPlan {
  assertSetupPlan(value);
  if (
    value.harness !== params.harness || value.harnessProfile !== params.hermesProfile ||
    (params.projectId !== null && !value.targetScopes.some(
      (scope) => scope.scope === 'project' && scope.projectId === params.projectId,
    )) ||
    value.targetScopes.some((scope) => scope.scope === 'project' && scope.projectId !== params.projectId)
  ) {
    throw new Error('Setup preview does not match the selection.');
  }
  return value;
}

export function requireHarnessAcknowledgment(value: unknown): void {
  if (!value || typeof value !== 'object' || Object.keys(value).length !== 1 ||
    !('kind' in value) || value.kind !== 'empty') {
    throw new Error('Setup operation was not acknowledged.');
  }
}
