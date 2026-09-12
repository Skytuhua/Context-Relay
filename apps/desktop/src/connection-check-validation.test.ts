import { expect, it } from 'vitest';
import * as validation from './protocol-validation';
const id = '018f22e2-79b0-7cc8-98c4-dc0c0c07398f';
const status = { checkId: id, selection: { harness: 'codex', projectId: id, hermesProfile: null }, memoryId: id, expectedRevision: id, phase: 'waiting', expiresInSeconds: 300, verifiedAt: null };
it('accepts only bounded connection status with a server verification time for verified receipts', () => {
  expect('validateConnectionCheckStatus' in validation).toBe(true);
  const validate = (validation as unknown as { validateConnectionCheckStatus(value: unknown): unknown }).validateConnectionCheckStatus;
  expect(validate(status)).toEqual(status);
  expect(() => validate({ ...status, phase: 'verified' })).toThrow();
  expect(() => validate({ ...status, expiresInSeconds: 301 })).toThrow();
  expect(() => validate({ ...status, selection: {...status.selection, projectId: null} })).toThrow();
  expect(() => validate({ ...status, secret: 'extra' })).toThrow();
  expect(validate({...status, phase: 'verified', verifiedAt: '1'})).toBeTruthy();
});
