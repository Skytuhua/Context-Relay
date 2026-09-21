import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { basename, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

export const VERSION = '0.1.1';
export const TAG = 'v0.1.1-alpha.1';
const workspace = fileURLToPath(new URL('../', import.meta.url));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const run = (command, args) => execFileSync(command, args, {
  cwd: workspace, encoding: 'utf8', windowsHide: true, maxBuffer: 64 * 1024 * 1024,
}).trim();

export function validateVersions(versions) {
  if (!versions.length || versions.some(version => version !== VERSION)) {
    throw new Error('Release version must be 0.1.1 across all manifests and workspace packages');
  }
}

export function hostedIdentity(url, key) {
  if (!/^sb_publishable_[A-Za-z0-9_-]+$/.test(key ?? '') || key.length > 4096) {
    throw new Error('A valid publishable key is required for a hosted preview');
  }
  let parsed;
  try { parsed = new URL(url); } catch { throw new Error('Invalid hosted URL'); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password ||
      parsed.pathname !== '/' || parsed.search || parsed.hash || parsed.port ||
      parsed.origin !== url || !/^[a-z0-9-]+\.supabase\.co$/.test(parsed.hostname)) {
    throw new Error('Hosted URL must be the HTTPS Supabase project origin');
  }
  return { url, publishable_key_sha256: hash(key) };
}

export function createSbom(cargo, nodeLicenses) {
  const components = [];
  function add(ecosystem, name, version, license) {
    if (!license || /UNKNOWN|UNLICENSED|SEE LICENSE/i.test(license)) {
      throw new Error(`Unknown license for ${name}`);
    }
    components.push({ type: 'library', name, version,
      purl: `pkg:${ecosystem}/${name.replace('@', '%40')}@${version}`,
      // Keep the upstream declaration as a named license. Cargo permits legacy
      // slash separators, which must not be mislabeled as SPDX expressions.
      licenses: [{ license: { name: license } }],
    });
  }
  for (const p of cargo.packages) add('cargo', p.name, p.version, p.license);
  for (const packages of Object.values(nodeLicenses)) {
    for (const p of packages) for (const version of p.versions) add('npm', p.name, version, p.license);
  }
  return { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
    metadata: { component: { type: 'application', name: 'Context Relay', version: VERSION },
      properties: [{ name: 'context-relay:scope', value: 'Windows-filtered Cargo and installed Node build dependencies; bundled resource inventory is in provenance.json' }] },
    components,
  };
}

export function verifyPublication(candidate, workflowRun, source, installerDigest) {
  if (!/^[a-f0-9]{40}$/.test(source) || !/^[a-f0-9]{64}$/.test(installerDigest)) throw new Error('Invalid source or digest');
  if (candidate.version !== VERSION || candidate.tag !== TAG || candidate.source_commit !== source ||
      candidate.target !== 'x86_64-pc-windows-msvc' || candidate.unsigned !== true ||
      !candidate.hosted?.url || !/^[a-f0-9]{64}$/.test(candidate.hosted?.publishable_key_sha256 ?? '') ||
      candidate.installer?.name !== `Context Relay_${VERSION}_x64-setup.exe`) throw new Error('Candidate identity mismatch');
  if (candidate.installer.sha256 !== installerDigest) throw new Error('Installer digest mismatch');
  if (workflowRun.head_sha !== source || workflowRun.head_branch !== 'main' ||
      workflowRun.repository?.full_name !== 'Skytuhua/Context-Relay' ||
      workflowRun.event !== 'workflow_dispatch' || workflowRun.conclusion !== 'success' ||
      workflowRun.path !== '.github/workflows/windows-package.yml' ||
      String(workflowRun.id) !== candidate.workflow.run_id ||
      String(workflowRun.run_attempt) !== candidate.workflow.run_attempt) throw new Error('Untrusted candidate workflow');
}

async function recordFile(path, name = basename(path)) {
  const bytes = await readFile(path);
  return { name, bytes: bytes.length, sha256: hash(bytes) };
}

// Tauri temporarily patches the desktop executable with the NSIS bundle type.
// The restored build-tree binary is not the byte sequence shipped in the installer.
export async function recordInstallerPayload(installerPath, resourceNames, extract = async (installer, directory) => {
  run('C:/Program Files/7-Zip/7z.exe', ['x', '-y', `-o${directory}`, installer]);
}) {
  const directory = await mkdtemp(join(tmpdir(), 'context-relay-payload-'));
  try {
    await extract(installerPath, directory);
    const binaries = await Promise.all(['context-relay-desktop', 'context-relay-contextd',
      'context-relay-context-mcp', 'context-relay-native-helper', 'context-relay-sidecar-installer']
      .map(name => recordFile(join(directory, `${name}.exe`))));
    const resources = await Promise.all(resourceNames.map(name => recordFile(join(directory, name), name)));
    const payload_files = [];
    async function visit(current) {
      for (const entry of await readdir(current, { withFileTypes: true })) {
        const path = join(current, entry.name);
        if (entry.isDirectory()) await visit(path);
        else if (entry.isFile()) payload_files.push(await recordFile(path, relative(directory, path).split(sep).join('/')));
        else throw new Error('Unexpected non-regular installer payload');
      }
    }
    await visit(directory);
    payload_files.sort((a, b) => a.name.localeCompare(b.name));
    return { binaries, resources, payload_files };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function candidateEvidence() {
  const metadata = JSON.parse(run('cargo', ['metadata', '--locked', '--format-version', '1', '--filter-platform', 'x86_64-pc-windows-msvc']));
  const versions = metadata.packages.filter(p => metadata.workspace_members.includes(p.id)).map(p => p.version);
  for (const file of ['package.json', 'apps/desktop/package.json', 'apps/desktop/src-tauri/tauri.conf.json']) {
    versions.push(JSON.parse(await readFile(join(workspace, file), 'utf8')).version);
  }
  validateVersions(versions);
  const hosted = hostedIdentity(process.env.CONTEXT_RELAY_HOSTED_URL, process.env.CONTEXT_RELAY_HOSTED_PUBLISHABLE_KEY);
  const output = join(metadata.target_directory, 'x86_64-pc-windows-msvc/release/bundle/nsis');
  const installers = (await readdir(output)).filter(name => name.endsWith('-setup.exe'));
  if (installers.length !== 1 || installers[0] !== `Context Relay_${VERSION}_x64-setup.exe`) throw new Error('Expected exactly one versioned preview installer');
  const installer = await recordFile(join(output, installers[0]));
  const bundle = JSON.parse(await readFile(join(workspace, 'apps/desktop/src-tauri/tauri.windows-release.conf.json'), 'utf8')).bundle;
  const { binaries, resources, payload_files } = await recordInstallerPayload(
    join(output, installers[0]), Object.values(bundle.resources));
  const node = JSON.parse(await readFile(join(workspace, 'target/node-licenses.json'), 'utf8'));
  const sbom = `${JSON.stringify(createSbom(metadata, node), null, 2)}\n`;
  const evidence = { version: VERSION, tag: TAG, source_commit: run('git', ['rev-parse', 'HEAD']),
    target: 'x86_64-pc-windows-msvc', unsigned: true, acceptance: 'pending installed and hosted qualification',
    hosted, installer, binaries, resources, payload_files,
    workflow: { run_id: process.env.GITHUB_RUN_ID ?? 'local', run_attempt: process.env.GITHUB_RUN_ATTEMPT ?? '1',
      ref: process.env.GITHUB_WORKFLOW_REF ?? 'local', sha: process.env.GITHUB_WORKFLOW_SHA ?? 'local',
      runner_image: process.env.ImageOS ?? process.platform, runner_image_version: process.env.ImageVersion ?? 'local' },
    toolchains: { node: process.version, pnpm: process.env.PNPM_VERSION, rust: run('rustc', ['-Vv']), cargo: run('cargo', ['-V']) },
    inputs: await Promise.all(['Cargo.lock', 'pnpm-lock.yaml', 'rust-toolchain.toml', '.node-version'].map(name => recordFile(join(workspace, name)))),
    sbom_sha256: hash(sbom),
  };
  await mkdir(output, { recursive: true });
  await writeFile(join(output, 'sbom.cdx.json'), sbom);
  const provenance = `${JSON.stringify(evidence, null, 2)}\n`;
  await writeFile(join(output, 'provenance.json'), provenance);
  await writeFile(join(output, 'SHA256SUMS'), `${installer.sha256}  ${installer.name}\n${hash(sbom)}  sbom.cdx.json\n${hash(provenance)}  provenance.json\n`);
  console.log(`Recorded unsigned candidate ${installer.name}: ${installer.sha256}; acceptance pending`);
}

async function publicationCheck(directory) {
  const candidate = JSON.parse(await readFile(join(directory, 'provenance.json'), 'utf8'));
  const runId = process.env.CANDIDATE_RUN_ID;
  if (!/^[1-9][0-9]*$/.test(runId ?? '')) throw new Error('Invalid candidate run ID');
  const workflowRun = JSON.parse(run('gh', ['api', `repos/Skytuhua/Context-Relay/actions/runs/${runId}`]));
  const environment = JSON.parse(run('gh', ['api', 'repos/Skytuhua/Context-Relay/environments/windows-preview-publication']));
  if (!environment.protection_rules?.some(rule => rule.type === 'required_reviewers' && rule.reviewers?.length > 0)) {
    throw new Error('Publication environment must require explicit reviewer approval');
  }
  const source = process.env.SOURCE_COMMIT;
  verifyPublication(candidate, workflowRun, source, process.env.INSTALLER_SHA256);
  const actual = await recordFile(join(directory, candidate.installer.name));
  if (actual.sha256 !== candidate.installer.sha256 || actual.bytes !== candidate.installer.bytes) throw new Error('Downloaded installer digest mismatch');
  if (hash(await readFile(join(directory, 'sbom.cdx.json'))) !== candidate.sbom_sha256) throw new Error('Downloaded SBOM digest mismatch');
  // fetch/merge-base are structured commands; source is already validated hex.
  run('git', ['fetch', '--no-tags', 'origin', 'main', `refs/tags/${TAG}:refs/tags/${TAG}`]);
  run('git', ['merge-base', '--is-ancestor', source, 'origin/main']);
  if (run('git', ['rev-parse', `${TAG}^{commit}`]) !== source) throw new Error('Protected tag does not name the accepted candidate');
  // Never overwrite or add to an existing release. gh release create also rejects it.
  console.log(`Verified ${TAG} candidate ${source} / ${actual.sha256}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === 'evidence' && process.argv.length === 3 && process.env.PNPM_VERSION === '11.9.0') await candidateEvidence();
  else if (process.argv[2] === 'verify-publication' && process.argv.length === 4) await publicationCheck(resolve(process.argv[3]));
  else throw new Error('Use evidence (with PNPM_VERSION=11.9.0 and target/node-licenses.json) or verify-publication <artifact-directory>');
}
