import { invoke } from '@tauri-apps/api/core';
import type { HarnessId, HarnessParams } from './bindings';

/** Presentation only. Native commands remain responsible for validating the platform and paths. */
export function harnessLaunchPresentation(userAgent = navigator.userAgent) {
  const canOpenWindow = userAgent.includes('Windows');
  return { canOpenWindow, terminal: canOpenWindow ? 'PowerShell' : 'Terminal' };
}

/** Opens an interactive terminal. The harness still owns sign-in and trust prompts. */
export function openHarness(selection: HarnessParams): Promise<void> {
  return invoke<void>('open_harness', { selection });
}

/** Call from the user's Copy command button; resolution and clipboard errors propagate. */
export async function copyHarnessCommand(selection: HarnessParams): Promise<void> {
  const command = await invoke<string>('harness_copy_command', { selection });
  await navigator.clipboard.writeText(command);
}

export function openHarnessGuide(harness: HarnessId): Promise<void> {
  return invoke<void>('open_harness_guide', { harness });
}
