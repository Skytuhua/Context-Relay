import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createProtocolSchemaValidator } from './protocol-validation';

type ComponentSchema = {
  properties: Record<string, Record<string, unknown>> & { kind: { const: string } };
};

const workspace = resolve(import.meta.dirname, '../../..');
const schemaRoot = resolve(process.env.CONTEXT_RELAY_SCHEMA_DIR ?? resolve(workspace, 'schemas'));
const loadWorkspace = (path: string) => JSON.parse(readFileSync(resolve(workspace, path), 'utf8'));
const loadSchema = (name: string) => JSON.parse(readFileSync(resolve(schemaRoot, name), 'utf8'));
const clone = <T>(value: T): T => structuredClone(value);

const ajv = createProtocolSchemaValidator();
const packageSchema = loadSchema('context-relay-package-v1.json');
const exportSchema = loadSchema('context-relay-export-v1.json');
const validatePackage = ajv.compile(packageSchema);
const validateExport = ajv.compile(exportSchema);
const validPackage = loadWorkspace('crates/protocol/tests/fixtures/package-v1-valid.json');
const extensionNamespace = 'dev.context-relay.fixture';
const validExport = loadWorkspace('crates/protocol/tests/fixtures/export-v1-valid.json');
const componentSchema = (kind: string): ComponentSchema => {
  const variants = packageSchema.properties.components.items.oneOf as ComponentSchema[];
  const found = variants.find((item) => item.properties.kind.const === kind);
  if (!found) throw new Error(`missing ${kind} schema`);
  return found;
};

describe('package and export schema parity', () => {
  it('accepts only canonical unpadded base64url for encrypted exports', () => {
    const exportWith = (value: string) => {
      const fixture = clone(validExport);
      fixture.records[0].encryptedPayload = value;
      return fixture;
    };

    expect(validateExport(exportWith('AQ'))).toBe(true);
    expect(validateExport(exportWith('AB'))).toBe(false);
  });

  it('accepts only bounded declarative namespaced extension data', () => {
    expect(validatePackage(validPackage), ajv.errorsText(validatePackage.errors)).toBe(true);

    const absent = clone(validPackage);
    delete absent.extensions;
    expect(validatePackage(absent), ajv.errorsText(validatePackage.errors)).toBe(true);

    const rawBytes = clone(validPackage);
    rawBytes.extensions = { [extensionNamespace]: { value: 'AQ' } };
    expect(validatePackage(rawBytes)).toBe(false);

    for (const key of [
      'password',
      'Client_Secret',
      'api-token',
      'session.cookie',
      'Private-Key',
      'credential',
      'executable',
      'binary',
      'Script',
      'shell',
      'run-command',
      'pre_hook',
      'sourceCode',
    ]) {
      const invalid = clone(validPackage);
      invalid.extensions[extensionNamespace].data = { [key]: 'not allowed' };
      expect(validatePackage(invalid), key).toBe(false);
    }

    for (const value of [
      'text\0with control',
      '-----BEGIN PRIVATE KEY-----not-a-real-key-----END PRIVATE KEY-----',
      '-----BEGIN RSA PRIVATE KEY-----not-a-real-key-----END RSA PRIVATE KEY-----',
      '-----BEGIN OPENSSH PRIVATE KEY-----not-a-real-key-----END OPENSSH PRIVATE KEY-----',
      '-----BEGIN ENCRYPTED PRIVATE KEY-----not-a-real-key-----END ENCRYPTED PRIVATE KEY-----',
    ]) {
      const invalid = clone(validPackage);
      invalid.extensions[extensionNamespace].data = { note: value };
      expect(validatePackage(invalid)).toBe(false);
    }

    const nested = clone(validPackage);
    nested.extensions[extensionNamespace].data = { nested: { value: 'no' } };
    expect(validatePackage(nested)).toBe(false);

    const tooMany = clone(validPackage);
    tooMany.extensions[extensionNamespace].data = Object.fromEntries(
      Array.from({ length: 65 }, (_, index) => [`item${index}`, 'value']),
    );
    expect(validatePackage(tooMany)).toBe(false);

    const longKey = clone(validPackage);
    longKey.extensions[extensionNamespace].data = { ['k'.repeat(129)]: 'value' };
    expect(validatePackage(longKey)).toBe(false);

    const longText = clone(validPackage);
    longText.extensions[extensionNamespace].data = { note: 'v'.repeat(16 * 1024 + 1) };
    expect(validatePackage(longText)).toBe(false);

    const unknown = clone(validPackage);
    unknown.extensions[extensionNamespace].ignored = true;
    expect(validatePackage(unknown)).toBe(false);

    const invalidNamespace = clone(validPackage);
    invalidNamespace.extensions = {
      'Invalid.Namespace': clone(invalidNamespace.extensions[extensionNamespace]),
    };
    expect(validatePackage(invalidNamespace)).toBe(false);

    const duplicate = clone(validPackage);
    duplicate.extensions = [
      { namespace: extensionNamespace, data: { first: 'value' } },
      { namespace: extensionNamespace, data: { first: 'value' } },
    ];
    expect(validatePackage(duplicate)).toBe(false);

    const sameNamespaceDifferentData = clone(validPackage);
    sameNamespaceDifferentData.extensions = [
      { namespace: extensionNamespace, data: { first: 'value' } },
      { namespace: extensionNamespace, data: { other: 'value' } },
    ];
    expect(validatePackage(sameNamespaceDifferentData)).toBe(false);
  });

  it('publishes Rust collection and text limits', () => {
    const instruction = componentSchema('instruction');
    const permission = componentSchema('permission_declaration');
    const skill = componentSchema('skill');

    expect(packageSchema.properties.components.maxItems).toBe(10_000);
    expect(packageSchema.properties.secretRefs.maxItems).toBe(10_000);
    expect(packageSchema.properties.extensions.maxProperties).toBe(10_000);
    expect(packageSchema.properties.harnessTargets.maxItems).toBe(3);
    expect(permission.properties.permissions).toMatchObject({ maxItems: 10_000, uniqueItems: true });
    expect(skill.properties.dependencies.maxItems).toBe(10_000);
    expect(instruction.properties.title.maxLength).toBe(512);
    expect(instruction.properties.title['x-utf8-maxBytes']).toBe(512);
    expect(instruction.properties.bodyMarkdown.maxLength).toBe(1_048_576);
    expect(exportSchema.properties.records.maxItems).toBe(10_000);
    expect(exportSchema.properties.operationOrder).toMatchObject({ maxItems: 10_000, uniqueItems: true });

    const oversizedUtf8 = clone(validPackage);
    oversizedUtf8.components[0].title = '\u00e9'.repeat(300);
    expect(validatePackage(oversizedUtf8)).toBe(false);
  });

  it('verifies canonical CBOR fixture hash metadata', () => {
    const fixture = loadWorkspace('crates/protocol/tests/fixtures/runtime-contracts-v1.json');
    for (const [name, metadata] of Object.entries(fixture.canonicalCbor) as [
      string,
      { file: string; sha256: string },
    ][]) {
      const hex = readFileSync(resolve(workspace, 'crates/protocol/tests/fixtures', metadata.file), 'utf8').trim();
      expect(createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex'), name).toBe(metadata.sha256);
    }
  });

  it('rejects out-of-range HLC values and unknown nested fields', () => {
    const maxHlc = clone(validExport);
    maxHlc.createdHlc.physicalMs = '18446744073709551615';
    expect(validateExport(maxHlc), ajv.errorsText(validateExport.errors)).toBe(true);

    const overflowHlc = clone(maxHlc);
    overflowHlc.createdHlc.physicalMs = '18446744073709551616';
    expect(validateExport(overflowHlc)).toBe(false);

    const unknownHlc = clone(validExport);
    unknownHlc.createdHlc.clockSource = 'wall';
    expect(validateExport(unknownHlc)).toBe(false);

    const unknownProvenance = clone(validExport);
    unknownProvenance.records[0].provenance.operator = 'server';
    expect(validateExport(unknownProvenance)).toBe(false);

    const unknownComponent = clone(validPackage);
    unknownComponent.components[0].shellCommand = 'ignored';
    expect(validatePackage(unknownComponent)).toBe(false);
  });
});
