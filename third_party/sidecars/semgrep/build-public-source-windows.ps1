param(
  [Parameter(Mandatory = $true)][string]$SourceLock,
  [Parameter(Mandatory = $true)][string]$SourceBundle,
  [Parameter(Mandatory = $true)][string]$WorkRoot,
  [Parameter(Mandatory = $true)][string]$OutputRoot,
  [Parameter(Mandatory = $true)][ValidateSet('build-a', 'build-b')][string]$BuildLabel,
  [switch]$OfflineBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Fail([string]$Message) { throw $Message }
function Invoke-Checked([scriptblock]$Command, [string]$Label) {
  & $Command
  if ($LASTEXITCODE -ne 0) { Fail "$Label failed with exit code $LASTEXITCODE" }
}

$ActionSha = '3e4c6ff8c9a04c9ec8f6f87701cd4b661b0f1f18'
$NodeActionSha = '49933ea5288caeca8642d1e84afbd3f7d6820020'
$CheckoutActionSha = 'df4cb1c069e1874edd31b4311f1884172cec0e10'
$UploadActionSha = '043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'
$DownloadActionSha = '37930b1c2abaa49bbe596cd826c3c89aef350131'
$SourceRevision = 'bd614accba811b407ae5c9ec6f1eecd3bdc29911'
$CompilerRevision = '3499e5708b0637c12d24d973dd103406a32b8fe8'
$TreeSitterSha = 'e2b687f74358ab6404730b7fb1a1ced7ddb3780202d37595ecd7b20a8f41861f'
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Workspace = [IO.Path]::GetFullPath((Join-Path $ScriptRoot '..\..\..'))
$CiProvenance = Join-Path $ScriptRoot 'native-ci-provenance.v1.json'
$Node = (Get-Command node.exe -ErrorAction Stop).Source
$Opam = (Get-Command opam.exe -ErrorAction Stop).Source
$Bash = (Get-Command bash.exe -ErrorAction Stop).Source
$Objdump = (Get-Command x86_64-w64-mingw32-objdump.exe -ErrorAction Stop).Source
$Gcc = (Get-Command x86_64-w64-mingw32-gcc.exe -ErrorAction Stop).Source
$Cygpath = (Get-Command cygpath.exe -ErrorAction Stop).Source
$Tar = (Resolve-Path -LiteralPath (Join-Path ([Environment]::SystemDirectory) 'tar.exe') -ErrorAction Stop).Path

$ClosedScanArguments = @(
  'scan',
  '--experimental',
  '--oss-only',
  '--metrics=off',
  '--disable-version-check',
  '--strict',
  '--error',
  '--json',
  '--quiet',
  '--no-git-ignore',
  '--x-ignore-semgrepignore-files',
  '--time',
  '--jobs=1',
  '--timeout=30',
  '--timeout-threshold=1',
  '--max-target-bytes=8388608'
)
function Invoke-ClosedScan(
  [string]$Executable,
  [string]$Config,
  [string]$Target,
  [string]$Stdout,
  [string]$Stderr
) {
  & $Executable @ClosedScanArguments '--config' $Config $Target 1> $Stdout 2> $Stderr
  return $LASTEXITCODE
}

function Normalize-SmokeEvidence(
  [string]$CleanPath,
  [string]$FindingPath,
  [string]$CleanStderrPath,
  [string]$FindingStderrPath,
  [string]$InvalidStderrPath
) {
  Invoke-Checked {
    & $Node -e '
      const fs = require("node:fs");
      const [cleanPath, findingPath, ...stderrPaths] = process.argv.slice(1);
      for (const path of [cleanPath, findingPath]) {
        const report = JSON.parse(fs.readFileSync(path, "utf8"));
        if (!Object.hasOwn(report, "time") || !report.time
            || typeof report.time !== "object" || Array.isArray(report.time)) {
          throw new Error(`missing volatile Semgrep timing object: ${path}`);
        }
        delete report.time;
        fs.writeFileSync(path, `${JSON.stringify(report)}\n`, { encoding: "utf8", flag: "w" });
      }
      const elapsedPrefix = /^\[\d+\.\d+\][ \t]*/gm;
      for (const path of stderrPaths) {
        const content = fs.readFileSync(path, "utf8");
        const matches = content.match(elapsedPrefix) ?? [];
        if (matches.length !== 1) throw new Error(`unexpected Semgrep elapsed-prefix count: ${path}`);
        const normalized = content.replace(elapsedPrefix, "");
        if (/^\[\d+\.\d+\]/m.test(normalized)) {
          throw new Error(`volatile Semgrep elapsed prefix remains: ${path}`);
        }
        fs.writeFileSync(path, normalized, { encoding: "utf8", flag: "w" });
      }
    ' $CleanPath $FindingPath $CleanStderrPath $FindingStderrPath $InvalidStderrPath
  } 'smoke evidence normalization'
}

if ($env:CONTEXT_RELAY_SETUP_OCAML_ACTION_SHA -ne $ActionSha) { Fail 'setup action identity mismatch' }
if ($env:CONTEXT_RELAY_SETUP_NODE_ACTION_SHA -ne $NodeActionSha) { Fail 'setup-node action identity mismatch' }
if ($env:CONTEXT_RELAY_RUNNER_IMAGE -ne 'windows-2022') { Fail 'runner image identity mismatch' }
if ((& $Node --version).Trim() -ne 'v24.14.0') { Fail 'Node v24.14.0 is required' }
if ((& $Opam --version) -ne '2.5.2') { Fail 'opam 2.5.2 is required' }
Invoke-Checked {
  & $Node -e '
    const fs = require("node:fs");
    const { createHash } = require("node:crypto");
    const [path, sourceLockPath, checkout, setupNode, setupOcaml, upload, download, compilerRevision] = process.argv.slice(1);
    const provenance = JSON.parse(fs.readFileSync(path, "utf8"));
    const sourceLockBytes = fs.readFileSync(sourceLockPath);
    const sourceLock = JSON.parse(sourceLockBytes);
    const sourceLockHash = createHash("sha256").update(sourceLockBytes).digest("hex");
    if (provenance.schemaVersion !== 1 || provenance.sourceLock?.sha256 !== sourceLockHash
        || provenance.sourceLock?.embeddedActionToolchainStatus !== "sealed-historical-metadata-non-authoritative-for-native-ci"
        || sourceLock.opam?.compiler?.package !== "ocaml-variants.5.3.0"
        || sourceLock.opam?.compiler?.revision !== compilerRevision) {
      throw new Error("native CI source lock identity mismatch");
    }
    const actionKey = ({ action, distributionTarget = "" }) => `${action}\0${distributionTarget}`;
    const actual = new Map(provenance.actions.map((entry) => [actionKey(entry), entry.revision]));
    const expected = new Map([
      ["actions/checkout\0", checkout],
      ["actions/setup-node\0", setupNode],
      ["semgrep/setup-ocaml\0aarch64-apple-darwin", "a739c5405d73c42ef15a9dc995efc0f87396cc36"],
      ["semgrep/setup-ocaml\0windows-x86_64", setupOcaml],
      ["actions/upload-artifact\0", upload],
      ["actions/download-artifact\0", download],
    ]);
    if (provenance.actions.length !== expected.size || actual.size !== expected.size
        || [...expected].some(([key, value]) => actual.get(key) !== value)) {
      throw new Error("native CI action provenance mismatch");
    }
    const toolchains = new Map(provenance.toolchains.map((entry) => [entry.distributionTarget, entry]));
    const value = toolchains.get("windows-x86_64");
    if (provenance.toolchains.length !== 2 || toolchains.size !== 2 || !value
        || value.runner !== "windows-2022" || value.ocamlCompiler !== "5.3.0"
        || value.opamVersion !== "2.5.2" || value.nodeVersion !== "24.14.0"
        || value.cygwinVersion !== "3.6.10"
        || value.setupNodeAction !== "actions/setup-node@" + setupNode
        || value.setupAction !== "semgrep/setup-ocaml@" + setupOcaml) {
      throw new Error("native CI toolchain provenance mismatch");
    }
  ' $CiProvenance $SourceLock $CheckoutActionSha $NodeActionSha $ActionSha $UploadActionSha $DownloadActionSha $CompilerRevision
} 'native CI action/toolchain provenance verification'
if ((& uname.exe -o) -ne 'Cygwin') { Fail 'the public Windows route requires Cygwin' }
$CygwinRelease = (& uname.exe -r).Trim()
if ($LASTEXITCODE -ne 0) { Fail 'Cygwin release detection failed' }
Invoke-Checked { & $Node (Join-Path $Workspace 'scripts\assert-cygwin-release.mjs') $CygwinRelease '3.6.10' } 'Cygwin release verification'
if ($SourceRevision -ne 'bd614accba811b407ae5c9ec6f1eecd3bdc29911') { Fail 'source identity mismatch' }

$WorkRoot = [IO.Path]::GetFullPath($WorkRoot)
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$forbidden = @([IO.Path]::GetPathRoot($WorkRoot), [Environment]::GetFolderPath('UserProfile'))
if ($forbidden -contains $WorkRoot -or $WorkRoot -match '[\r\n]' -or $WorkRoot -match '\s' -or $WorkRoot.Contains('#')) { Fail 'unsafe WorkRoot' }
if (Test-Path -LiteralPath $WorkRoot) { Fail 'WorkRoot must not already exist' }
if (Test-Path -LiteralPath $OutputRoot) { Fail 'OutputRoot must not already exist' }

Invoke-Checked { & $Node (Join-Path $Workspace 'scripts\semgrep-source-bundle.mjs') --verify $SourceLock $SourceBundle | Out-Null } 'source bundle verification'
New-Item -ItemType Directory -Path $WorkRoot, $OutputRoot | Out-Null
$env:LC_ALL = 'C'
$env:TZ = 'UTC'
$env:SOURCE_DATE_EPOCH = '0'
$env:OPAMYES = '1'
$env:OPAMCOLOR = 'never'
$env:OPAMDOWNLOADJOBS = '1'
$env:OPAMJOBS = '1'
$env:DUNEJOBS = '1'
$env:MAKEFLAGS = '-j1'
$env:OPAMRETRIES = '0'
$env:HTTP_PROXY = 'http://127.0.0.1:9'
$env:HTTPS_PROXY = 'http://127.0.0.1:9'
$env:ALL_PROXY = 'http://127.0.0.1:9'

$script:Current = $null
function Add-Pin([string]$Package, [string]$Revision) {
  Invoke-Checked { & $Opam pin add --no-action $Package (Join-Path $script:Current "bundle\pins\$Revision") } "pin $Package"
}

function Initialize-CompilerGitIdentity([string]$GitDir, [string]$Revision) {
  $GitDirForward = [IO.Path]::GetFullPath($GitDir).Replace('\', '/')
  if ($GitDirForward -notmatch '^[A-Za-z]:/') { Fail 'compiler Git directory is not an absolute Windows drive path' }
  # The verified local rsync pin has no VCS metadata, but the fork's configure
  # script embeds `git rev-parse HEAD` in the compiler version.
  Invoke-Checked {
    & $Bash -c 'set -eu; git init --bare "$1" >/dev/null; printf "%s\n" "$2" > "$1/HEAD"; test "$(git --git-dir="$1" rev-parse HEAD)" = "$2"' _ $GitDirForward $Revision
  } 'compiler Git identity preparation'
  return $GitDirForward
}

function Assert-CompilerIdentity([string]$Revision) {
  $ExpectedPinPath = [IO.Path]::GetFullPath((Join-Path $script:Current "bundle\pins\$Revision")).Replace('\', '/')
  if ($ExpectedPinPath -notmatch '^[A-Za-z]:/') { Fail 'compiler pin path is not an absolute Windows drive path' }
  $ExpectedPinUrl = "file://$ExpectedPinPath"
  $PinOutput = @(& $Opam pin list --normalise)
  if ($LASTEXITCODE -ne 0) { Fail 'compiler pin identity query failed' }
  $CompilerPins = @($PinOutput | Where-Object { $_ -match '^ocaml-variants\.5\.3\.0\s+' })
  if ($CompilerPins.Count -ne 1) { Fail 'compiler pin identity is missing or ambiguous' }
  $PinFields = @($CompilerPins[0].Trim() -split '\s+')
  if ($PinFields.Count -ne 3 -or $PinFields[1] -ne 'rsync') { Fail 'compiler pin transport mismatch' }
  $PinUrl = $PinFields[2].Replace('\', '/')
  if (-not $PinUrl.StartsWith('file://', [StringComparison]::Ordinal) -or
      -not [string]::Equals($PinUrl, $ExpectedPinUrl, [StringComparison]::Ordinal)) { Fail 'compiler pin path mismatch' }
  $CompilerVersion = (& $Opam exec -- ocamlc -version).Trim()
  if ($LASTEXITCODE -ne 0) { Fail 'compiler embedded identity query failed' }
  if ($CompilerVersion -ne "5.3.0+semgrep-fork@$Revision") { Fail 'compiler embedded identity mismatch' }
}

function Test-OutboundTcp([Net.IPAddress]$Address) {
  $Client = [Net.Sockets.TcpClient]::new($Address.AddressFamily)
  try {
    $Connect = $Client.ConnectAsync($Address, 443)
    if (-not $Connect.Wait([TimeSpan]::FromSeconds(8))) { return $false }
    return $Client.Connected
  } catch {
    return $false
  } finally {
    $Client.Dispose()
  }
}

function Get-RunnerControlPlanePrograms {
  $RequiredNames = @('Runner.Worker.exe', 'Runner.Listener.exe')
  $Found = @{}
  $Visited = [Collections.Generic.HashSet[uint32]]::new()
  [uint32]$CurrentProcessId = $PID
  while ($CurrentProcessId -ne 0 -and $Visited.Add($CurrentProcessId)) {
    $Process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $CurrentProcessId" -ErrorAction Stop
    if ($null -eq $Process) { break }
    $Name = [IO.Path]::GetFileName([string]$Process.ExecutablePath)
    if ($RequiredNames -contains $Name) {
      if ([string]::IsNullOrWhiteSpace([string]$Process.ExecutablePath)) { Fail "runner executable path is empty: $Name" }
      $Resolved = (Resolve-Path -LiteralPath ([string]$Process.ExecutablePath) -ErrorAction Stop).Path
      $Item = Get-Item -LiteralPath $Resolved -Force
      if (-not $Item.PSIsContainer -and (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) {
        $Found[$Name] = $Resolved
      } else {
        Fail "runner executable path is not a regular file: $Name"
      }
    }
    [uint32]$ParentProcessId = $Process.ParentProcessId
    if ($ParentProcessId -eq $CurrentProcessId) { break }
    $CurrentProcessId = $ParentProcessId
  }
  foreach ($Name in $RequiredNames) {
    if (-not $Found.ContainsKey($Name)) { Fail "runner control-plane ancestor not found: $Name" }
  }
  $Directories = @($RequiredNames | ForEach-Object { Split-Path -Parent $Found[$_] } | Select-Object -Unique)
  if ($Directories.Count -ne 1) { Fail 'runner control-plane executables do not share one trusted directory' }
  return [string[]]@($RequiredNames | ForEach-Object { $Found[$_] })
}

function Test-DnsResolverAddress([Net.IPAddress]$Address) {
  if ($Address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -and
      $Address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6) { return $false }
  return -not [Net.IPAddress]::IsLoopback($Address) -and
    -not $Address.Equals([Net.IPAddress]::Any) -and
    -not $Address.Equals([Net.IPAddress]::IPv6Any) -and
    -not $Address.IsIPv6Multicast
}

function Test-TrustedDllPath([string]$Path, [string[]]$TrustedDllRoots) {
  $Resolved = [IO.Path]::GetFullPath($Path)
  foreach ($Root in $TrustedDllRoots) {
    $Prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    if ($Resolved.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) { return $true }
  }
  return $false
}

function Build-Once([string]$Label) {
  $script:Current = Join-Path $WorkRoot 'current'
  if (Test-Path -LiteralPath $script:Current) { Remove-Item -LiteralPath $script:Current -Recurse -Force }
  $Bundle = Join-Path $script:Current 'bundle'
  New-Item -ItemType Directory -Path $Bundle, (Join-Path $script:Current 'home'), (Join-Path $script:Current 'tmp') | Out-Null
  Invoke-Checked { & $Tar -xf $SourceBundle -C $Bundle } 'source bundle extraction'
  Invoke-Checked { & $Node (Join-Path $Workspace 'scripts\semgrep-source-bundle.mjs') --materialize-links $Bundle | Out-Null } 'source link materialization'
  Invoke-Checked {
    & $Node (Join-Path $Bundle 'support\scripts\apply-semgrep-source-patches.mjs') `
      (Join-Path $Bundle 'support\third_party\sidecars\semgrep\patches.v1.json') `
      $Bundle | Out-Null
  } 'source patch application'
  $Project = Join-Path $Bundle 'sources\semgrep'
  if (-not (Test-Path -LiteralPath (Join-Path $Project 'Makefile') -PathType Leaf)) { Fail 'Semgrep source is missing' }

  $TreeSitterDownloads = Join-Path $Project 'libs\ocaml-tree-sitter-core\downloads'
  New-Item -ItemType Directory -Force -Path $TreeSitterDownloads | Out-Null
  $TreeArchive = Join-Path $Bundle "opam-repository\cache\sha256\$($TreeSitterSha.Substring(0, 2))\$TreeSitterSha"
  Invoke-Checked { & $Tar -xf $TreeArchive -C $TreeSitterDownloads } 'tree-sitter source extraction'
  if (-not (Test-Path -LiteralPath (Join-Path $TreeSitterDownloads 'tree-sitter-0.22.6') -PathType Container)) { Fail 'tree-sitter source did not unpack as expected' }

  $env:HOME = Join-Path $script:Current 'home'
  $env:TMP = Join-Path $script:Current 'tmp'
  $env:TEMP = $env:TMP
  $env:OPAMROOT = Join-Path $script:Current 'opam'
  $Repository = Join-Path $Bundle 'opam-repository'
  Invoke-Checked { & $Opam init --bare --no-setup --no-cygwin-setup default $Repository } 'opam init'
  $CachePath = (Join-Path $Repository 'cache').Replace('\', '/')
  if ($CachePath -notmatch '^[A-Za-z]:/') { Fail 'offline archive mirror is not an absolute Windows drive path' }
  $CacheUri = "file://$CachePath"
  $ArchiveMirrorsOption = 'archive-mirrors=["{0}"]' -f $CacheUri
  Invoke-Checked { & $Opam option --global $ArchiveMirrorsOption } 'offline archive mirror'
  $Switch = Join-Path $script:Current 'switch'
  Invoke-Checked { & $Opam switch create $Switch --empty } 'empty switch creation'
  $env:OPAMSWITCH = $Switch

  $CompilerGitDirForward = Initialize-CompilerGitIdentity (Join-Path $script:Current 'compiler-git') $CompilerRevision
  Add-Pin 'ocaml-variants.5.3.0' $CompilerRevision
  if ($null -ne [Environment]::GetEnvironmentVariable('GIT_DIR', 'Process')) { Fail 'GIT_DIR must be unset before compiler installation' }
  $env:GIT_DIR = $CompilerGitDirForward
  try {
    Invoke-Checked { & $Opam install --update-invariant 'ocaml-variants.5.3.0' } 'compiler installation'
  } finally {
    Remove-Item Env:GIT_DIR -ErrorAction SilentlyContinue
  }
  Add-Pin 'pcre2.dev' '4e0a44486bb518b7a24ca11286c4b03a8d51e17e'
  Add-Pin 'tree-sitter.dev' 'c4baff8d83b2e1f83f247acb11d0c9dafa5e48f7'
  foreach ($Package in @('testo.dev', 'testo-util.dev', 'testo-diff.dev', 'testo-lwt.dev')) { Add-Pin $Package 'df18ea541c75c9acf75923218586c5ffe8915a04' }
  Add-Pin 'obackward.dev' 'e1c16766976b4fadd97097b96f96666e8e1cb98c'
  Add-Pin 'semgrep-interfaces.dev' '7e509db48c700cae49fe0372e2aa0410fa86d867'
  foreach ($Package in @('pyro-caml-instruments.dev', 'pyro-caml-ppx.dev')) { Add-Pin $Package 'ef59d6c39085079bb7d2ea76b3d4c7a7d4ec27d9' }
  foreach ($Package in @('opentelemetry.dev', 'opentelemetry-client-ocurl.dev', 'opentelemetry-client-cohttp-eio.dev', 'opentelemetry-logs.dev')) { Add-Pin $Package '6cfa5f16d85ac65b602f732469b667bac4aca5ac' }
  Add-Pin 'memtrace.dev' 'a88470c3de884182503ba5fcd4729e281e544731'

  Push-Location $Project
  try {
    Invoke-Checked { & $Bash './scripts/pick-lockfile.sh' '--strict' 'semgrep.opam' } 'lockfile selection'
    Invoke-Checked { & $Bash '-c' 'cd libs/ocaml-tree-sitter-core && patch -N -b -i patch/tree-sitter-0.22.6/0001-Makefile-backports.patch downloads/tree-sitter-0.22.6/Makefile' } 'tree-sitter source patch'
    Invoke-Checked { & $Bash '-c' 'cd libs/ocaml-tree-sitter-core && ./configure && ./scripts/install-tree-sitter-lib' } 'tree-sitter build'
    $env:OPAMIGNOREPINDEPENDS = 'true'
    Invoke-Checked { & $Opam install --locked --update-invariant --deps-only '.\semgrep.opam' } 'dependency installation'
    Assert-CompilerIdentity $CompilerRevision
    Invoke-Checked { & $Opam exec -- make core } 'osemgrep build'
  } finally {
    Pop-Location
  }

  $Executable = Join-Path $Project '_build\install\default\bin\osemgrep.exe'
  if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) { Fail 'osemgrep.exe was not built' }
  $Destination = Join-Path $OutputRoot $Label
  $Evidence = Join-Path $OutputRoot "$Label-evidence"
  New-Item -ItemType Directory -Path $Destination, $Evidence | Out-Null
  Copy-Item -LiteralPath $Executable -Destination (Join-Path $Destination 'osemgrep.exe')

  $CygwinRoot = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $Bash) '..'))
  $TrustedDllRoots = [string[]]@(
    $Destination,
    (Join-Path $Project '_build'),
    (Join-Path $Project '_build\install\default\bin'),
    (Join-Path $script:Current 'switch'),
    (Join-Path $script:Current 'switch\bin'),
    (Split-Path -Parent $Gcc),
    (Split-Path -Parent $Bash),
    $CygwinRoot,
    (Join-Path $CygwinRoot 'usr\x86_64-w64-mingw32\sys-root\mingw\bin')
  ) | Where-Object { Test-Path -LiteralPath $_ -PathType Container } | ForEach-Object {
    (Resolve-Path -LiteralPath $_).Path
  } | Select-Object -Unique

  $SystemDlls = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Name in @('advapi32.dll','bcrypt.dll','crypt32.dll','dnsapi.dll','gdi32.dll','iphlpapi.dll','kernel32.dll','msvcrt.dll','ntdll.dll','ole32.dll','oleaut32.dll','secur32.dll','shell32.dll','user32.dll','userenv.dll','version.dll','winhttp.dll','winmm.dll','ws2_32.dll')) { [void]$SystemDlls.Add($Name) }
  $Queue = [Collections.Generic.Queue[string]]::new()
  $Queue.Enqueue((Join-Path $Destination 'osemgrep.exe'))
  $Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Dependencies = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  while ($Queue.Count -gt 0) {
    $Binary = $Queue.Dequeue()
    $Output = & $Objdump -p $Binary
    if ($LASTEXITCODE -ne 0) { Fail "objdump failed for $Binary" }
    foreach ($Line in $Output) {
      if ($Line -notmatch '^\s*DLL Name:\s*(\S+)\s*$') { continue }
      $Name = $Matches[1]
      [void]$Dependencies.Add($Name)
      if ($Name -match '(?i)python') { Fail 'Python runtime dependency detected' }
      if ($SystemDlls.Contains($Name) -or $Name -match '^(?i)(api|ext)-ms-win-') { continue }
      if (-not $Seen.Add($Name)) { continue }
      $Candidate = $null
      foreach ($Directory in $TrustedDllRoots) {
        $FromTrustedRoot = Join-Path $Directory $Name
        if (Test-Path -LiteralPath $FromTrustedRoot -PathType Leaf) { $Candidate = $FromTrustedRoot; break }
      }
      if ($null -eq $Candidate) {
        $CompilerCandidate = (& $Gcc "-print-file-name=$Name").Trim()
        if ($LASTEXITCODE -ne 0) { Fail "compiler DLL lookup failed: $Name" }
        if ($CompilerCandidate.StartsWith('/')) {
          $CompilerCandidate = (& $Cygpath -w $CompilerCandidate).Trim()
          if ($LASTEXITCODE -ne 0) { Fail "compiler DLL path conversion failed: $Name" }
        }
        if ($CompilerCandidate -ne $Name -and (Test-Path -LiteralPath $CompilerCandidate -PathType Leaf)) {
          $Candidate = $CompilerCandidate
        }
      }
      if ($null -eq $Candidate) { Fail "unresolved runtime DLL: $Name" }
      $Candidate = (Resolve-Path -LiteralPath $Candidate).Path
      if (-not (Test-TrustedDllPath $Candidate $TrustedDllRoots)) { Fail "untrusted runtime DLL path: $Candidate" }
      if ((Get-Item -LiteralPath $Candidate).Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "untrusted runtime DLL path: $Candidate" }
      $Copied = Join-Path $Destination $Name
      Copy-Item -LiteralPath $Candidate -Destination $Copied
      $Queue.Enqueue($Copied)
    }
  }
  $Dependencies | Sort-Object | Set-Content -LiteralPath (Join-Path $Evidence 'runtime-dependencies.txt') -Encoding Ascii
  $SmokeFixtures = Join-Path $script:Current 'smoke-fixtures'
  $SmokeHome = Join-Path $script:Current 'smoke-home'
  $SmokeTmp = Join-Path $script:Current 'smoke-tmp'
  New-Item -ItemType Directory -Force -Path $SmokeFixtures, $SmokeHome, $SmokeTmp | Out-Null
  $Utf8NoBom = [Text.UTF8Encoding]::new($false)
  [IO.File]::WriteAllLines(
    (Join-Path $SmokeFixtures 'rule.yml'),
    [string[]]@(
      'rules:',
      '  - id: context-relay-smoke',
      '    languages: [generic]',
      '    severity: ERROR',
      '    message: Context Relay native smoke finding',
      '    pattern: context-relay-finding'
    ),
    $Utf8NoBom
  )
  [IO.File]::WriteAllLines((Join-Path $SmokeFixtures 'invalid-rule.yml'), [string[]]@('rules: ['), $Utf8NoBom)
  [IO.File]::WriteAllLines((Join-Path $SmokeFixtures 'clean.txt'), [string[]]@('clean target'), $Utf8NoBom)
  [IO.File]::WriteAllLines((Join-Path $SmokeFixtures 'finding.txt'), [string[]]@('context-relay-finding'), $Utf8NoBom)
  return [pscustomobject]@{
    Destination = $Destination
    Evidence = $Evidence
    SmokeFixtures = $SmokeFixtures
    SmokeHome = $SmokeHome
    SmokeTmp = $SmokeTmp
  }
}

function Invoke-RuntimeSmoke([pscustomobject]$Build) {
  $Destination = $Build.Destination
  $Evidence = $Build.Evidence
  $SmokeFixtures = $Build.SmokeFixtures
  $SmokeHome = $Build.SmokeHome
  $SmokeTmp = $Build.SmokeTmp
  $SavedEnvironment = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Entry in Get-ChildItem Env:) { $SavedEnvironment[$Entry.Name] = $Entry.Value }
  $EnvironmentNames = [string[]]@(Get-ChildItem Env: | ForEach-Object Name)
  $ClosedEnvironment = [ordered]@{
    SystemRoot = $env:SystemRoot
    WINDIR = $env:WINDIR
    SystemDrive = $env:SystemDrive
    ComSpec = $env:ComSpec
    OS = 'Windows_NT'
    PROCESSOR_ARCHITECTURE = 'AMD64'
    NUMBER_OF_PROCESSORS = $env:NUMBER_OF_PROCESSORS
    PATH = "$Destination;$env:SystemRoot\System32"
    HOME = $SmokeHome
    USERPROFILE = $SmokeHome
    APPDATA = (Join-Path $SmokeHome 'AppData\Roaming')
    LOCALAPPDATA = (Join-Path $SmokeHome 'AppData\Local')
    TMP = $SmokeTmp
    TEMP = $SmokeTmp
    LC_ALL = 'C'
    LANG = 'C'
    TZ = 'UTC'
    HTTP_PROXY = 'http://127.0.0.1:9'
    HTTPS_PROXY = 'http://127.0.0.1:9'
    ALL_PROXY = 'http://127.0.0.1:9'
  }
  New-Item -ItemType Directory -Force -Path $ClosedEnvironment.APPDATA, $ClosedEnvironment.LOCALAPPDATA | Out-Null
  $SmokeLocationPushed = $false
  try {
    foreach ($Name in $EnvironmentNames) {
      [Environment]::SetEnvironmentVariable($Name, $null, 'Process')
    }
    foreach ($Pair in $ClosedEnvironment.GetEnumerator()) {
      [Environment]::SetEnvironmentVariable([string]$Pair.Key, [string]$Pair.Value, 'Process')
    }
    Push-Location -LiteralPath $SmokeFixtures
    $SmokeLocationPushed = $true
    $RuntimeExecutable = Join-Path $Destination 'osemgrep.exe'
    $VersionOutput = [string[]]@(& $RuntimeExecutable --experimental --version)
    if ($LASTEXITCODE -ne 0) { Fail "no-Python version smoke failed with exit code $LASTEXITCODE" }
    [IO.File]::WriteAllLines((Join-Path $Evidence 'version.txt'), $VersionOutput, [Text.Encoding]::ASCII)

    $CleanJson = Join-Path $Evidence 'clean.json'
    $CleanStatus = Invoke-ClosedScan $RuntimeExecutable 'rule.yml' 'clean.txt' $CleanJson (Join-Path $Evidence 'clean.stderr')
    if ($CleanStatus -ne 0) { Fail "closed clean scan failed with exit code $CleanStatus" }
    $CleanReport = Get-Content -Raw -LiteralPath $CleanJson | ConvertFrom-Json
    if (@($CleanReport.results).Count -ne 0 -or @($CleanReport.errors).Count -ne 0) { Fail 'closed clean scan results were not zero' }

    $FindingJson = Join-Path $Evidence 'finding.json'
    $FindingStatus = Invoke-ClosedScan $RuntimeExecutable 'rule.yml' 'finding.txt' $FindingJson (Join-Path $Evidence 'finding.stderr')
    if ($FindingStatus -ne 1) { Fail "closed finding scan returned unexpected exit code $FindingStatus" }
    $FindingReport = Get-Content -Raw -LiteralPath $FindingJson | ConvertFrom-Json
    if (@($FindingReport.results).Count -ne 1 -or @($FindingReport.errors).Count -ne 0) { Fail 'closed finding scan results were not one' }
    if ($FindingReport.results[0].check_id -ne 'context-relay-smoke') { Fail 'closed finding scan returned the wrong rule' }

    $InvalidStatus = Invoke-ClosedScan $RuntimeExecutable 'invalid-rule.yml' 'clean.txt' (Join-Path $Evidence 'invalid.json') (Join-Path $Evidence 'invalid.stderr')
    if ($InvalidStatus -eq 0 -or $InvalidStatus -eq 1) { Fail 'invalid rule did not produce a distinct config failure' }
    $InvalidEvidence = [IO.File]::ReadAllText((Join-Path $Evidence 'invalid.json')) + [IO.File]::ReadAllText((Join-Path $Evidence 'invalid.stderr'))
    if ($InvalidEvidence -notmatch '(?i)invalid|error|parse|config|yaml') { Fail 'invalid rule evidence lacks a parse or config error' }
    Normalize-SmokeEvidence $CleanJson $FindingJson (Join-Path $Evidence 'clean.stderr') (Join-Path $Evidence 'finding.stderr') (Join-Path $Evidence 'invalid.stderr')
  } finally {
    if ($SmokeLocationPushed) { Pop-Location }
    foreach ($Name in [string[]]@(Get-ChildItem Env: | ForEach-Object Name)) {
      [Environment]::SetEnvironmentVariable($Name, $null, 'Process')
    }
    foreach ($Pair in $SavedEnvironment.GetEnumerator()) {
      [Environment]::SetEnvironmentVariable($Pair.Key, $Pair.Value, 'Process')
    }
  }
  $RuntimeNames = [string[]]@(Get-ChildItem -LiteralPath $Destination -File | ForEach-Object Name)
  [Array]::Sort($RuntimeNames, [StringComparer]::Ordinal)
  $ManifestLines = [string[]]@($RuntimeNames | ForEach-Object {
    "$(Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $Destination $_) | Select-Object -ExpandProperty Hash)  $_".ToLowerInvariant()
  })
  [IO.File]::WriteAllLines((Join-Path $Evidence 'MANIFEST.sha256'), $ManifestLines, [Text.Encoding]::ASCII)
}

$Build = if ($OfflineBuild) { $null } else { Build-Once $BuildLabel }
$ProbeAddress = [Net.Dns]::GetHostAddresses('github.com') |
  Where-Object AddressFamily -eq ([Net.Sockets.AddressFamily]::InterNetwork) |
  Select-Object -First 1
if ($null -eq $ProbeAddress -or -not (Test-OutboundTcp $ProbeAddress)) {
  Fail 'outbound TCP preflight failed before enabling offline firewall policy'
}
$RunnerPrograms = @(Get-RunnerControlPlanePrograms)
$RunnerProgramHashes = @{}
foreach ($Program in $RunnerPrograms) {
  $RunnerProgramHashes[$Program] = (Get-FileHash -Algorithm SHA256 -LiteralPath $Program).Hash
}
$ResolverSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($Resolver in @(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object ServerAddresses)) {
  [Net.IPAddress]$Address = $null
  if (-not [Net.IPAddress]::TryParse([string]$Resolver, [ref]$Address) -or
      -not (Test-DnsResolverAddress $Address)) { continue }
  [void]$ResolverSet.Add($Address.ToString())
}
$ResolverAddresses = [string[]]@($ResolverSet)
[Array]::Sort($ResolverAddresses, [StringComparer]::Ordinal)
if ($ResolverAddresses.Count -eq 0 -or $ResolverAddresses.Count -gt 16) {
  Fail 'configured DNS resolver address set is missing or unbounded'
}
$ProfileSnapshots = @(foreach ($ProfileName in @('Domain', 'Private', 'Public')) {
  $Profile = Get-NetFirewallProfile -Profile $ProfileName -ErrorAction Stop
  [pscustomobject]@{
    Name = $Profile.Name
    DefaultOutboundAction = [string]$Profile.DefaultOutboundAction
  }
})
$FirewallPrefix = "ContextRelaySemgrepOffline-$PID-$([Guid]::NewGuid().ToString('N'))"
$RunnerRuleNames = [Collections.Generic.List[string]]::new()
$DnsRuleNames = [Collections.Generic.List[string]]::new()
$DisabledOutboundRuleNames = [Collections.Generic.List[string]]::new()
try {
  $RuleIndex = 0
  foreach ($Program in $RunnerPrograms) {
    $RuleIndex += 1
    $RuleName = "$FirewallPrefix-Runner-$RuleIndex"
    $RunnerRuleNames.Add($RuleName)
    New-NetFirewallRule -Name $RuleName -DisplayName $RuleName -Direction Outbound -Program $Program -RemoteAddress Any -RemotePort 443 -Protocol TCP -Action Allow -Profile Any -ErrorAction Stop | Out-Null
    $Rule = Get-NetFirewallRule -Name $RuleName -PolicyStore ActiveStore -ErrorAction Stop
    $Application = $Rule | Get-NetFirewallApplicationFilter
    $AddressFilter = $Rule | Get-NetFirewallAddressFilter
    $Port = $Rule | Get-NetFirewallPortFilter
    if ($Rule.Enabled -ne 'True' -or
        $Rule.Direction -ne 'Outbound' -or
        $Rule.Action -ne 'Allow' -or
        [IO.Path]::GetFullPath($Application.Program) -ne [IO.Path]::GetFullPath($Program) -or
        [string]$AddressFilter.RemoteAddress -cne 'Any' -or
        [string]$Port.RemotePort -cne '443' -or
        @('TCP', '6') -notcontains [string]$Port.Protocol) {
      Fail 'runner control-plane firewall allow rule is not exact and active'
    }
  }

  $DnsProgram = [IO.Path]::GetFullPath((Join-Path ([Environment]::SystemDirectory) 'svchost.exe'))
  foreach ($Protocol in @('UDP', 'TCP')) {
    $RuleName = "$FirewallPrefix-Dns-$Protocol"
    $DnsRuleNames.Add($RuleName)
    New-NetFirewallRule -Name $RuleName -DisplayName $RuleName -Direction Outbound -Program $DnsProgram -Service Dnscache -RemoteAddress $ResolverAddresses -RemotePort 53 -Protocol $Protocol -Action Allow -Profile Any -ErrorAction Stop | Out-Null
  }

  $ExistingOutboundAllows = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True |
    Where-Object { $RunnerRuleNames -notcontains $_.Name -and $DnsRuleNames -notcontains $_.Name })
  foreach ($ExistingRule in $ExistingOutboundAllows) {
    if ([string]$ExistingRule.PolicyStoreSourceType -ne 'Local' -or [string]::IsNullOrWhiteSpace($ExistingRule.Name)) {
      Fail "non-local outbound allow rule prevents fail-closed isolation: $($ExistingRule.DisplayName)"
    }
    $DisabledOutboundRuleNames.Add($ExistingRule.Name)
    Disable-NetFirewallRule -Name $ExistingRule.Name -ErrorAction Stop | Out-Null
  }
  $RemainingBroadAllows = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True |
    Where-Object { $RunnerRuleNames -notcontains $_.Name -and $DnsRuleNames -notcontains $_.Name })
  if ($RemainingBroadAllows.Count -ne 0) { Fail 'outbound allow rules remain outside the runner control-plane carveout' }

  foreach ($ProfileSnapshot in $ProfileSnapshots) {
    Set-NetFirewallProfile -Profile $ProfileSnapshot.Name -DefaultOutboundAction Block -ErrorAction Stop
  }
  foreach ($ProfileSnapshot in $ProfileSnapshots) {
    $Effective = Get-NetFirewallProfile -Profile $ProfileSnapshot.Name -ErrorAction Stop
    if ([string]$Effective.DefaultOutboundAction -ne 'Block') { Fail "offline default outbound policy is not active: $($ProfileSnapshot.Name)" }
  }
  if (Test-OutboundTcp $ProbeAddress) { Fail 'hostile outbound TCP probe bypassed the offline firewall policy' }
  if ($OfflineBuild) { $Build = Build-Once $BuildLabel }
  Invoke-RuntimeSmoke $Build
  foreach ($Program in $RunnerPrograms) {
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $Program).Hash -ne $RunnerProgramHashes[$Program]) {
      Fail "runner control-plane executable changed during the runtime smoke: $Program"
    }
  }
  foreach ($ProfileSnapshot in $ProfileSnapshots) {
    $Effective = Get-NetFirewallProfile -Profile $ProfileSnapshot.Name -ErrorAction Stop
    if ([string]$Effective.DefaultOutboundAction -ne 'Block') { Fail "offline firewall policy changed during the runtime smoke: $($ProfileSnapshot.Name)" }
  }
  if (Test-OutboundTcp $ProbeAddress) { Fail 'offline firewall policy was removed during the runtime smoke' }
  [IO.File]::WriteAllText(
    (Join-Path $OutputRoot "$BuildLabel.offline-egress.v1.json"),
    '{"mechanism":"' + $(if ($OfflineBuild) { 'windows-firewall-default-outbound-block-hash-pinned-runner-tcp443-allow' } else { 'windows-firewall-runtime-smoke-network-deny' }) + '","probe":"hostile-outbound-tcp-denied","schemaVersion":1}' + "`n",
    [Text.UTF8Encoding]::new($false)
  )
} finally {
  $RestoreFailures = [Collections.Generic.List[string]]::new()
  foreach ($ProfileSnapshot in $ProfileSnapshots) {
    try {
      Set-NetFirewallProfile -Profile $ProfileSnapshot.Name -DefaultOutboundAction $ProfileSnapshot.DefaultOutboundAction -ErrorAction Stop
      $Restored = Get-NetFirewallProfile -Profile $ProfileSnapshot.Name -ErrorAction Stop
      if ([string]$Restored.DefaultOutboundAction -ne $ProfileSnapshot.DefaultOutboundAction) {
        throw "restored value differs: $($Restored.DefaultOutboundAction)"
      }
    } catch {
      $RestoreFailures.Add("profile $($ProfileSnapshot.Name): $($_.Exception.Message)")
    }
  }
  foreach ($RuleName in $DisabledOutboundRuleNames) {
    try {
      Enable-NetFirewallRule -Name $RuleName -ErrorAction Stop | Out-Null
      $RestoredRule = Get-NetFirewallRule -Name $RuleName -PolicyStore ActiveStore -ErrorAction Stop
      if ($RestoredRule.Enabled -ne 'True') { throw 'rule is not enabled' }
    } catch {
      $RestoreFailures.Add("outbound rule ${RuleName}: $($_.Exception.Message)")
    }
  }
  foreach ($RuleName in [string[]]@($RunnerRuleNames + $DnsRuleNames)) {
    try {
      if (Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -Name $RuleName -ErrorAction Stop
      }
      if (Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue) { throw 'rule still exists' }
    } catch {
      $RestoreFailures.Add("isolation allow rule ${RuleName}: $($_.Exception.Message)")
    }
  }
  Clear-DnsClientCache -ErrorAction SilentlyContinue
  if ($RestoreFailures.Count -ne 0) { Fail "firewall restoration failed: $($RestoreFailures -join '; ')" }
}
if ($OfflineBuild) {
  Write-Output "Windows Cygwin/MinGW public-source $BuildLabel build and runtime smoke completed with network denial."
} else {
  Write-Output "Windows Cygwin/MinGW public-source $BuildLabel runtime smoke completed with network denial."
}
