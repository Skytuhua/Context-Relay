import { Buffer } from 'node:buffer';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));

import { LocalWorkspaceGateway } from './workspace';

beforeEach(() => {
  invoke.mockReset().mockResolvedValue({ kind: 'empty' });
});

afterEach(() => vi.restoreAllMocks());

it.each([
  'C:\\Users\\Alice\\Documents\\專案',
  'C:\\Users\\Alice\\Projects\\🚀 research',
  'C:\\Projects\\lone-\ud800-surrogate',
])('preserves every Windows UTF-16 code unit when binding %s', async (path) => {
  vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue('Windows NT 10.0');
  await new LocalWorkspaceGateway().createProject('Project', path);

  const wirePath = invoke.mock.calls[1][1].request.params.path;
  expect(wirePath.platform).toBe('windows');
  expect(wirePath.display).toBe(path);
  expect(Buffer.from(wirePath.bytes, 'base64url')).toEqual(Buffer.from(path, 'utf16le'));
});

it('keeps macOS paths encoded as UTF-8', async () => {
  vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue('Macintosh; Intel Mac OS X');
  const path = '/Users/alice/專案/🚀 research';
  await new LocalWorkspaceGateway().createProject('Project', path);

  const wirePath = invoke.mock.calls[1][1].request.params.path;
  expect(wirePath.platform).toBe('macos');
  expect(Buffer.from(wirePath.bytes, 'base64url')).toEqual(Buffer.from(path, 'utf8'));
});

it('accepts a Windows Copy as path value without binding its surrounding quotes', async () => {
  vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue('Windows NT 10.0');
  await new LocalWorkspaceGateway().createProject('Project', '"C:\\Users\\Alice\\Projects\\🚀 research"');
  const wirePath = invoke.mock.calls[1][1].request.params.path;
  expect(wirePath.display).toBe('C:\\Users\\Alice\\Projects\\🚀 research');
  expect(Buffer.from(wirePath.bytes, 'base64url').toString('utf16le')).toBe('C:\\Users\\Alice\\Projects\\🚀 research');
});

it('preserves literal quotation marks in macOS paths', async () => {
  vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue('Macintosh; Intel Mac OS X');
  await new LocalWorkspaceGateway().createProject('Project', '/Users/alice/"research"');
  const wirePath = invoke.mock.calls[1][1].request.params.path;
  expect(Buffer.from(wirePath.bytes, 'base64url').toString('utf8')).toBe('/Users/alice/"research"');
});
