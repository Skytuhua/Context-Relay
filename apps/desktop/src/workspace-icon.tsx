const paths = {
  home: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  memory: 'M5 3h11l3 3v15H5z M8 9h8 M8 13h8 M8 17h5',
  tasks: 'M9 5h12 M9 12h12 M9 19h12 M2 5l2 2 3-4 M2 12l2 2 3-4 M2 19l2 2 3-4',
  harnesses: 'M8 8H6a4 4 0 0 0 0 8h4 M16 8h2a4 4 0 0 1 0 8h-4 M8 12h8',
  projects: 'M3 7h7l2-3h9v16H3z',
  help: 'M9 9a3 3 0 1 1 5 2c-2 1-2 2-2 3 M12 17h.01 M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20',
  settings: 'M4 6h16 M4 12h16 M4 18h16 M8 3v6 M16 9v6 M10 15v6',
};

export function WorkspaceIcon({ name }: { name: string }) {
  return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false"><path d={paths[name as keyof typeof paths] ?? paths.memory} /></svg>;
}
