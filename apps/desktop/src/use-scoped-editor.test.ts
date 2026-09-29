import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { useScopedEditor } from './use-scoped-editor';

afterEach(cleanup);

it('hides an old editor even if a caller bypasses the normal project transition', () => {
  const note = { id: 'note-a' };
  const { result, rerender } = renderHook(({ projectId }: { projectId: string | null }) => useScopedEditor<typeof note>(projectId), { initialProps: { projectId: 'a' as string | null } });
  act(() => result.current[1](note));
  expect(result.current[0]).toBe(note);
  rerender({ projectId: 'b' });
  expect(result.current[0]).toBeNull();
  rerender({ projectId: null });
  expect(result.current[0]).toBeNull();
});

it('does not relabel a late callback from A as a selection in B', () => {
  const { result, rerender } = renderHook(({ projectId }) => useScopedEditor<{ id: string }>(projectId), { initialProps: { projectId: 'a' } });
  const selectA = result.current[1];
  rerender({ projectId: 'b' });
  act(() => selectA({ id: 'late-a' }));
  expect(result.current[0]).toBeNull();
});

it('restores into the destination scope rather than the originating render scope', () => {
  const { result, rerender } = renderHook(({ projectId }) => useScopedEditor<{ id: string }>(projectId), { initialProps: { projectId: 'a' } });
  const noteB = { id: 'note-b' };
  act(() => result.current[2](noteB, 'b'));
  expect(result.current[0]).toBeNull();
  rerender({ projectId: 'b' });
  expect(result.current[0]).toBe(noteB);
  act(() => result.current[1](current => current?.id === noteB.id ? null : current));
  expect(result.current[0]).toBeNull();
});
