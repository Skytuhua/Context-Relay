import assert from 'node:assert/strict';
import test from 'node:test';

import { LICENSE, REPOSITORY, validateMetadata } from './check-license-metadata.mjs';

test('accepts canonical first-party metadata', () => {
  assert.doesNotThrow(() =>
    validateMetadata([{ name: 'context-relay', license: LICENSE, repository: REPOSITORY }]),
  );
});

test('rejects missing or unknown first-party license metadata', () => {
  assert.throws(() => validateMetadata([{ name: 'missing' }]));
  assert.throws(() =>
    validateMetadata([{ name: 'unknown', license: 'Proprietary', repository: REPOSITORY }]),
  );
});
