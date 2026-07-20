import { resolve } from 'node:path';

export function acceptsCygwinRelease(release, version) {
  return typeof release === 'string'
    && typeof version === 'string'
    && /^\d+(?:\.\d+){2}$/u.test(version)
    && (release === version || ['-', '+', '.', '('].includes(release[version.length]))
    && release.startsWith(version);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  const [release, version] = process.argv.slice(2);
  if (!acceptsCygwinRelease(release, version)) {
    process.stderr.write(`Cygwin ${version ?? '<missing>'} is required\n`);
    process.exitCode = 1;
  }
}
