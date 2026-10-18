import { execFileSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { resolve } from 'node:path';

const documentationFiles = new Set([
  'README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md',
  'TRADEMARKS.md', 'LICENSE', 'NOTICE',
]);
const frontendFiles = new Set([
  'apps/desktop/index.html', 'apps/desktop/vite.config.ts',
  'apps/desktop/tsconfig.json', 'apps/desktop/eslint.config.js',
]);

export function requiresRustTests(paths) {
  // Native inputs extend beyond Rust source: fixtures, schemas, scripts,
  // dependency pins and third-party material can all change the test result.
  // Only this explicit frontend/documentation set is safe to skip.
  return paths.some((path) => !(
    documentationFiles.has(path)
    || frontendFiles.has(path)
    || /^docs\/[^\r\n]+\.md$/u.test(path)
    || /^apps\/desktop\/src\/[^\r\n]+\.(?:ts|tsx|css|svg)$/u.test(path)
  ));
}

export function determineRustTestScope({
  cwd = process.cwd(), eventName, baseSha, headSha, force = false,
}) {
  if (force || eventName !== 'pull_request') {
    return { runTests: true, reason: 'Rust tests required for this event.' };
  }
  if (![baseSha, headSha].every((sha) => typeof sha === 'string' && /^[0-9a-f]{40}$/u.test(sha))) {
    return { runTests: true, reason: 'No usable comparison commits; running Rust tests.' };
  }
  try {
    const git = (...args) => execFileSync('git', args, {
      cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    });
    git('cat-file', '-e', `${baseSha}^{commit}`);
    git('cat-file', '-e', `${headSha}^{commit}`);
    // NUL delimiters preserve unusual filenames, and disabling rename
    // detection keeps both the old and new path in the scope decision.
    const changed = git('diff', '--name-only', '--no-renames', '-z', baseSha, headSha, '--');
    const paths = changed.split('\0').filter(Boolean);
    if (requiresRustTests(paths)) {
      return { runTests: true, reason: 'Native or unclassified files changed; running Rust tests.' };
    }
    return { runTests: false, reason: 'Rust tests skipped: only frontend or documentation files changed.' };
  } catch {
    return { runTests: true, reason: 'Unable to establish the changed files; running Rust tests.' };
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  const decision = determineRustTestScope({
    eventName: process.env.EVENT_NAME,
    baseSha: process.env.PR_BASE_SHA,
    headSha: process.env.CURRENT_SHA,
    force: process.env.FORCE_RUST_TESTS === 'true',
  });
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `run_tests=${decision.runTests}\n`);
  }
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${decision.reason}\n`);
  }
  console.log(decision.reason);
}
