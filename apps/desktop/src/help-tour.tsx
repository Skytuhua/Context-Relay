import { useEffect, useRef } from 'react';

export function HelpScreen({ onResumeSetup, onStartTour, setupComplete = false }: { onResumeSetup: () => void; onStartTour: () => void; setupComplete?: boolean }) {
  return <div className="help-content">
    <p>Context Relay keeps useful notes and project progress available between coding sessions. This guide is available offline.</p>
    <div className="form-actions"><button className="primary-action" onClick={onResumeSetup}>{setupComplete ? 'Set up harnesses' : 'Resume setup'}</button><button onClick={onStartTour}>Start tour</button></div>
    <section><h2>Projects</h2><p>A project groups the context and tasks for one folder of work. Choose it in the project selector before saving a note or task.</p><p>For example, keep your website’s decisions separate from your mobile app’s decisions.</p></section>
    <section><h2>Saved context</h2><p>Context is a note your coding assistant can use in future sessions: a preference, decision, fact, or procedure.</p><p>Open Context, choose Saved, then Add context. Give the note a clear title and save it. For example: “Use clear, plain language and explain unfamiliar terms.”</p></section>
    <section><h2>Suggestions</h2><p>A suggestion is a possible note proposed by your harness. It waits for your review before becoming saved context.</p><p>Open Context, then Suggestions. Read the proposed note and its evidence. Accept useful notes; reject details you do not want to keep.</p></section>
    <section><h2>Tasks</h2><p>A task records work to do, its progress, and what to try next. It helps you resume a coding session without rebuilding the whole plan.</p><p>Open Tasks, choose New task, and describe the next concrete step. For example: “Check the sign-in error message.” Update progress as you work and include a summary when completing it.</p></section>
    <section><h2>Harnesses and connections</h2><p>A harness is the coding assistant you use: Codex, Claude Code, or Hermes. Open Harnesses to review and save the settings that let it use Context Relay.</p><p>Settings saved means the configuration was written. Your harness may still ask you to trust the project or approve access. Resume setup and verify a test note to check that the harness can read this project’s context.</p><details><summary>How this works</summary><p>MCP is the connection your harness uses to request context. A hook runs at a session event, such as starting work, to help bring context into the session. Your harness controls its own trust and approval prompts; approve them there after reviewing what they allow.</p><p>A preview describes proposed settings changes. Save applies the reviewed changes; Undo uses the recorded setup to restore the previous settings. If an operation is interrupted, open Harnesses and follow its recovery instructions.</p></details></section>
    <section><h2>Settings and devices</h2><p>Open Settings to choose Dark, Light, or System appearance. Devices shows computers paired with your workspace. Pair another device when you want to use your context there.</p><details><summary>When something does not load or save</summary><p>Check that Context Relay is running, then use the page’s Retry action. If a save was not confirmed, review the saved recovery copy before trying again. Keep recovery words private; they help you regain access to encrypted data.</p></details></section>
  </div>;
}

const parts = [
  { title: 'Choose your project', text: 'The project selector keeps context and tasks tied to the work you are doing. Change projects there whenever you switch folders.', screen: 'home', action: 'Show Dashboard' },
  { title: 'Keep useful context', text: 'Open Context to save preferences, decisions, and notes your harness can use next time. Start with one clear note, such as how you like explanations written.', screen: 'memory', action: 'Show saved context' },
  { title: 'Review suggestions', text: 'Your harness can propose notes. Read them in Suggestions, then accept what is useful or reject what you do not want to keep.', screen: 'review', action: 'Show suggestions' },
  { title: 'Continue a task', text: 'Tasks keep progress and the next step together. Create a task, update its progress, and add a completion summary when the work is done.', screen: 'tasks', action: 'Show tasks' },
  { title: 'Manage your harnesses', text: 'Harnesses shows setup and recovery actions for Codex, Claude Code, and Hermes. Settings saved is one step; use guided setup to verify that your harness can read a test note.', screen: 'harnesses', action: 'Show harnesses' },
] as const;

export function DashboardTour({ step, onStep, onClose, onNavigate }: {
  step: number; onStep: (step: number) => void; onClose: () => void;
  onNavigate: (screen: 'home' | 'memory' | 'review' | 'tasks' | 'harnesses') => void;
}) {
  const index = Math.max(0, Math.min(4, Math.trunc(step) || 0));
  const part = parts[index];
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, [index]);
  return <aside className="tour-panel" aria-labelledby="tour-title">
    <p role="status" aria-live="polite" aria-atomic="true">Part {index + 1} of 5 · {part.title}</p>
    <h2 id="tour-title" ref={heading} tabIndex={-1}>{part.title}</h2>
    <p>{part.text}</p>
    <div className="form-actions">
      <button onClick={() => onNavigate(part.screen)}>{part.action}</button>
      <button disabled={index === 0} onClick={() => onStep(index - 1)}>Back</button>
      {index < 4 ? <button className="primary" onClick={() => onStep(index + 1)}>Next</button> : <button className="primary" onClick={onClose}>Finish tour</button>}
      <button onClick={onClose}>Skip tour</button>
    </div>
  </aside>;
}
