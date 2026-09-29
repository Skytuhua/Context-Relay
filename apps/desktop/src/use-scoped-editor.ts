import { useState, type SetStateAction } from 'react';

type Selection<T> = { projectId: string | null; record: T };

/** A project change cannot expose or submit an editor selected in another scope. */
export function useScopedEditor<T>(projectId: string | null) {
  const [selection, setSelection] = useState<Selection<T> | null>(null);
  const record = selection?.projectId === projectId ? selection.record : null;

  function select(update: SetStateAction<T | null>) {
    setSelection(current => {
      const visible = current?.projectId === projectId ? current.record : null;
      const next = typeof update === 'function'
        ? (update as (value: T | null) => T | null)(visible)
        : update;
      return next === null ? null : { projectId, record: next };
    });
  }

  // Project transitions restore into the destination scope, not the scope of
  // the render whose callback initiated that transition.
  function restore(record: T | null, nextProjectId: string | null) {
    setSelection(record === null ? null : { projectId: nextProjectId, record });
  }

  return [record, select, restore] as const;
}
