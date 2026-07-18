import Ajv2020 from 'ajv/dist/2020.js';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

type ComponentSchema = {
  properties: Record<string, Record<string, unknown>> & { kind: { const: string } };
};

const workspace = resolve(import.meta.dirname, '../../..');
const schemaRoot = resolve(process.env.CONTEXT_RELAY_SCHEMA_DIR ?? resolve(workspace, 'schemas'));
const loadWorkspace = (path: string) => JSON.parse(readFileSync(resolve(workspace, path), 'utf8'));
const loadSchema = (name: string) => JSON.parse(readFileSync(resolve(schemaRoot, name), 'utf8'));
const clone = <T>(value: T): T => structuredClone(value);

const ajv = new Ajv2020({ allErrors: true, strict: true });
const packageSchema = loadSchema('context-relay-package-v1.json');
const exportSchema = loadSchema('context-relay-export-v1.json');
const validatePackage = ajv.compile(packageSchema);
const validateExport = ajv.compile(exportSchema);
const validPackage = loadWorkspace('crates/protocol/tests/fixtures/package-v1-valid.json');
const validExport = loadWorkspace('crates/protocol/tests/fixtures/export-v1-valid.json');
const componentSchema = (kind: string): ComponentSchema => {
  const variants = packageSchema.properties.components.items.oneOf as ComponentSchema[];
  const found = variants.find((item) => item.properties.kind.const === kind);
  if (!found) throw new Error(`missing ${kind} schema`);
  return found;
};

describe('package and export schema parity', () => {
  it('accepts only canonical unpadded base64url', () => {
    const packageWith = (value: string) => {
      const fixture = clone(validPackage);
      fixture.extensions[0].value = value;
      return fixture;
    };
    const exportWith = (value: string) => {
      const fixture = clone(validExport);
      fixture.records[0].encryptedPayload = value;
      return fixture;
    };

    expect(validatePackage(packageWith('AQ'))).toBe(true);
    expect(validatePackage(packageWith('AB'))).toBe(false);
    expect(validateExport(exportWith('AQ'))).toBe(true);
    expect(validateExport(exportWith('AB'))).toBe(false);
  });

  it('publishes Rust collection and text limits', () => {
    const instruction = componentSchema('instruction');
    const permission = componentSchema('permission_declaration');
    const skill = componentSchema('skill');

    expect(packageSchema.properties.components.maxItems).toBe(10_000);
    expect(packageSchema.properties.secretRefs.maxItems).toBe(10_000);
    expect(packageSchema.properties.extensions.maxItems).toBe(10_000);
    expect(packageSchema.properties.harnessTargets.maxItems).toBe(3);
    expect(permission.properties.permissions).toMatchObject({ maxItems: 10_000, uniqueItems: true });
    expect(skill.properties.dependencies.maxItems).toBe(10_000);
    expect(instruction.properties.title.maxLength).toBe(512);
    expect(instruction.properties.bodyMarkdown.maxLength).toBe(1_048_576);
    expect(exportSchema.properties.records.maxItems).toBe(10_000);
    expect(exportSchema.properties.operationOrder).toMatchObject({ maxItems: 10_000, uniqueItems: true });
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
