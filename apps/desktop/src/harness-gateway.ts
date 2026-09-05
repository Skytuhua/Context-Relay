import type { HarnessParams, PlanId, SetupPlan } from './bindings';
import * as protocolValidation from './protocol-validation';

const assertSetupPlan: (value: unknown) => asserts value is SetupPlan = protocolValidation.assertSetupPlan;

export interface HarnessGateway {
  harnessPreview(params: HarnessParams): Promise<SetupPlan>;
  harnessApply(planId: PlanId): Promise<void>;
  harnessRollback(planId: PlanId): Promise<void>;
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
