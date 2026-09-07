param([string]$CacheDirectory = (Join-Path $PSScriptRoot '../target/search-assets'))

$ErrorActionPreference = 'Stop'
$CacheDirectory = [IO.Path]::GetFullPath($CacheDirectory)
$downloads = Join-Path $CacheDirectory '.downloads'
$sevenZip = 'C:/Program Files/7-Zip/7z.exe'
if (!(Test-Path -LiteralPath $sevenZip -PathType Leaf)) { throw '7-Zip is required to extract verified archives' }
New-Item -ItemType Directory -Force -Path $downloads | Out-Null

function Test-PinnedFile($Path, $Bytes, $Sha256) {
    (Test-Path -LiteralPath $Path -PathType Leaf) -and
        (Get-Item -LiteralPath $Path).Length -eq $Bytes -and
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -eq $Sha256
}

function Get-PinnedFile($Uri, $Path, $Bytes, $Sha256) {
    if (Test-PinnedFile $Path $Bytes $Sha256) { return }
    $partial = "$Path.partial"
    & curl.exe --fail --location --silent --show-error --max-time 180 --max-filesize $Bytes --output $partial $Uri
    if ($LASTEXITCODE -ne 0) { throw "Download failed: $Uri" }
    if (!(Test-PinnedFile $partial $Bytes $Sha256)) { throw "Downloaded asset does not match its manifest: $Path" }
    Move-Item -LiteralPath $partial -Destination $Path -Force
}

function Expand-PinnedArchive($Archive, $Destination, $Members) {
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    & $sevenZip e -y "-o$Destination" $Archive @Members | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Archive extraction failed: $Archive" }
}

$modelManifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../crates/core/models/bge-small-en-v1.5/manifest.json') -Raw | ConvertFrom-Json
$modelDirectory = Join-Path $CacheDirectory 'bge-small-en-v1.5'
New-Item -ItemType Directory -Force -Path $modelDirectory | Out-Null
foreach ($artifact in $modelManifest.artifacts) {
    $uri = "https://huggingface.co/$($modelManifest.model)/resolve/$($modelManifest.revision)/$($artifact.file)"
    Get-PinnedFile $uri (Join-Path $modelDirectory $artifact.file) $artifact.bytes $artifact.sha256
}

$ortArchive = Join-Path $downloads 'onnxruntime-win-x64-1.24.2.zip'
Get-PinnedFile 'https://github.com/microsoft/onnxruntime/releases/download/v1.24.2/onnxruntime-win-x64-1.24.2.zip' $ortArchive 74075355 '8e3e9c826375352e29cb2614fe44f3d7a4b0ff7b8028ad7a456af9d949a7e8b0'
$ortDirectory = Join-Path $downloads 'ort'
Expand-PinnedArchive $ortArchive $ortDirectory @(
    'onnxruntime-win-x64-1.24.2/lib/onnxruntime.dll',
    'onnxruntime-win-x64-1.24.2/lib/onnxruntime_providers_shared.dll',
    'onnxruntime-win-x64-1.24.2/LICENSE',
    'onnxruntime-win-x64-1.24.2/ThirdPartyNotices.txt'
)

# This is passive extraction only: neither the redistributable EXE nor any MSI
# is executed. The exact Microsoft archive is pinned by its WinGet manifest.
$redist = Join-Path $downloads 'VC_redist.14.44.35211.x64.exe'
Get-PinnedFile 'https://download.visualstudio.microsoft.com/download/pr/73aabf2e-9532-4f68-99f7-3247081a619c/CC0FF0EB1DC3F5188AE6300FAEF32BF5BEEBA4BDD6E8E445A9184072096B713B/VC_redist.x64.exe' $redist 25635768 'cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b'
$redistBytes = [IO.File]::ReadAllBytes($redist)
# Attached cabinet offset/size for this exact hash; a12 is its x64 minimum CRT
# cabinet, as recorded in the archive's Burn manifest.
$payload = New-Object byte[] 24939223
[Array]::Copy($redistBytes, 686152, $payload, 0, $payload.Length)
$cabinet = Join-Path $downloads 'redist-payload.cab'
[IO.File]::WriteAllBytes($cabinet, $payload)
$payloadDirectory = Join-Path $downloads 'redist-payload'
Expand-PinnedArchive $cabinet $payloadDirectory @('a12')
$crtDirectory = Join-Path $downloads 'crt'
Expand-PinnedArchive (Join-Path $payloadDirectory 'a12') $crtDirectory @(
    'vcruntime140.dll_amd64', 'vcruntime140_1.dll_amd64', 'msvcp140.dll_amd64', 'msvcp140_1.dll_amd64'
)

$runtimeManifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../crates/core/models/onnxruntime-win-x64-1.24.2/manifest.json') -Raw | ConvertFrom-Json
$runtimeDirectory = Join-Path $CacheDirectory 'runtime'
New-Item -ItemType Directory -Force -Path $runtimeDirectory | Out-Null
foreach ($artifact in $runtimeManifest.artifacts) {
    $source = if ($artifact.file -match '^(vcruntime|msvcp)') {
        Join-Path $crtDirectory "$($artifact.file)_amd64"
    } else { Join-Path $ortDirectory $artifact.file }
    if (!(Test-PinnedFile $source $artifact.bytes $artifact.sha256)) { throw "Extracted runtime asset mismatch: $($artifact.file)" }
    Copy-Item -LiteralPath $source -Destination (Join-Path $runtimeDirectory $artifact.file) -Force
}
Write-Output "Verified search assets: $CacheDirectory"
