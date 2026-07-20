#!/bin/sh
set -eu

die() { printf '%s\n' "$*" >&2; exit 1; }
test "$#" -eq 5 || die "usage: $0 SOURCE_LOCK SOURCE_BUNDLE.tar WORK_ROOT OUTPUT_ROOT BUILD_LABEL"

SOURCE_LOCK=$1
SOURCE_BUNDLE=$2
WORK_ROOT=$3
OUTPUT_ROOT=$4
BUILD_LABEL=$5
ACTION_SHA=a739c5405d73c42ef15a9dc995efc0f87396cc36
NODE_ACTION_SHA=49933ea5288caeca8642d1e84afbd3f7d6820020
CHECKOUT_ACTION_SHA=df4cb1c069e1874edd31b4311f1884172cec0e10
UPLOAD_ACTION_SHA=043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
DOWNLOAD_ACTION_SHA=37930b1c2abaa49bbe596cd826c3c89aef350131
SOURCE_REVISION=bd614accba811b407ae5c9ec6f1eecd3bdc29911
TREE_SITTER_SHA=e2b687f74358ab6404730b7fb1a1ced7ddb3780202d37595ecd7b20a8f41861f
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
WORKSPACE=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd -P)
CI_PROVENANCE=$SCRIPT_DIR/native-ci-provenance.v1.json
NODE=${NODE:-node}

case "$BUILD_LABEL" in build-a|build-b) ;; *) die "BUILD_LABEL must be build-a or build-b" ;; esac

test "$(uname -s)" = Darwin || die "the public macOS route requires Darwin"
test "$(uname -m)" = arm64 || die "the public macOS route requires arm64"
test "${CONTEXT_RELAY_SETUP_OCAML_ACTION_SHA:-}" = "$ACTION_SHA" || die "setup action identity mismatch"
test "${CONTEXT_RELAY_SETUP_NODE_ACTION_SHA:-}" = "$NODE_ACTION_SHA" || die "setup-node action identity mismatch"
test "${CONTEXT_RELAY_RUNNER_IMAGE:-}" = macos-15 || die "runner image identity mismatch"
test "$("$NODE" --version)" = v24.14.0 || die "Node v24.14.0 is required"
test "$(opam --version)" = 2.5.0 || die "opam 2.5.0 is required"
"$NODE" -e '
  const fs = require("node:fs");
  const { createHash } = require("node:crypto");
  const [path, sourceLockPath, checkout, setupNode, setupOcaml, upload, download] = process.argv.slice(1);
  const provenance = JSON.parse(fs.readFileSync(path, "utf8"));
  const sourceLockHash = createHash("sha256").update(fs.readFileSync(sourceLockPath)).digest("hex");
  if (provenance.schemaVersion !== 1 || provenance.sourceLock?.sha256 !== sourceLockHash
      || provenance.sourceLock?.embeddedActionToolchainStatus !== "sealed-historical-metadata-non-authoritative-for-native-ci") {
    throw new Error("native CI source lock identity mismatch");
  }
  const actionKey = ({ action, distributionTarget = "" }) => `${action}\0${distributionTarget}`;
  const actual = new Map(provenance.actions.map((entry) => [actionKey(entry), entry.revision]));
  const expected = new Map([
    ["actions/checkout\0", checkout],
    ["actions/setup-node\0", setupNode],
    ["semgrep/setup-ocaml\0aarch64-apple-darwin", setupOcaml],
    ["semgrep/setup-ocaml\0windows-x86_64", "3e4c6ff8c9a04c9ec8f6f87701cd4b661b0f1f18"],
    ["actions/upload-artifact\0", upload],
    ["actions/download-artifact\0", download],
  ]);
  if (provenance.actions.length !== expected.size || actual.size !== expected.size
      || [...expected].some(([key, value]) => actual.get(key) !== value)) {
    throw new Error("native CI action provenance mismatch");
  }
  const toolchains = new Map(provenance.toolchains.map((entry) => [entry.distributionTarget, entry]));
  const value = toolchains.get("aarch64-apple-darwin");
  if (provenance.toolchains.length !== 2 || toolchains.size !== 2 || !value || value.runner !== "macos-15"
      || value.ocamlCompiler !== "ocaml-variants.5.3.0+options,ocaml-option-flambda"
      || value.opamVersion !== "2.5.0" || value.nodeVersion !== "24.14.0"
      || value.setupNodeAction !== `actions/setup-node@${setupNode}`
      || value.setupAction !== `semgrep/setup-ocaml@${setupOcaml}`) {
    throw new Error("native CI toolchain provenance mismatch");
  }
' "$CI_PROVENANCE" "$SOURCE_LOCK" "$CHECKOUT_ACTION_SHA" "$NODE_ACTION_SHA" "$ACTION_SHA" "$UPLOAD_ACTION_SHA" "$DOWNLOAD_ACTION_SHA"
command -v otool >/dev/null
command -v shasum >/dev/null
test -x /usr/bin/sandbox-exec || die "macOS sandbox-exec is required for an offline build"
case "$WORK_ROOT" in /*) ;; *) die "WORK_ROOT must be absolute" ;; esac
case "$OUTPUT_ROOT" in /*) ;; *) die "OUTPUT_ROOT must be absolute" ;; esac
case "$WORK_ROOT" in /|"$HOME"|*[[:space:]]*) die "unsafe WORK_ROOT" ;; esac
test ! -e "$WORK_ROOT" || die "WORK_ROOT must not already exist"
test ! -e "$OUTPUT_ROOT" || die "OUTPUT_ROOT must not already exist"

assert_network_denied() {
  "$NODE" -e '
    const net = require("node:net");
    const timer = setTimeout(() => process.exit(72), 3000);
    const socket = net.createConnection({ host: "1.1.1.1", port: 443 });
    socket.once("connect", () => process.exit(73));
    socket.once("error", (error) => {
      clearTimeout(timer);
      process.exit(error.code === "EPERM" || error.code === "EACCES" ? 0 : 74);
    });
  ' || die "macOS sandbox did not deny the hostile outbound TCP probe"
}

if test "${CONTEXT_RELAY_MACOS_NETWORK_SANDBOX:-}" != active; then
  SANDBOX_PROFILE=$(mktemp "${TMPDIR:-/tmp}/context-relay-semgrep.sb.XXXXXX")
  trap 'rm -f "$SANDBOX_PROFILE"' 0 HUP INT TERM
  printf '%s\n' \
    '(version 1)' \
    '(allow default)' \
    '(deny network*)' > "$SANDBOX_PROFILE"
  set +e
  CONTEXT_RELAY_MACOS_NETWORK_SANDBOX=active \
    /usr/bin/sandbox-exec -f "$SANDBOX_PROFILE" /bin/sh "$0" "$@"
  BUILD_STATUS=$?
  set -e
  rm -f "$SANDBOX_PROFILE"
  exit "$BUILD_STATUS"
fi
assert_network_denied

"$NODE" "$WORKSPACE/scripts/semgrep-source-bundle.mjs" --verify "$SOURCE_LOCK" "$SOURCE_BUNDLE" >/dev/null
mkdir -p "$WORK_ROOT" "$OUTPUT_ROOT"
umask 022
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=0 OPAMYES=1 OPAMCOLOR=never OPAMDOWNLOADJOBS=1 OPAMRETRIES=0
export HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9
export http_proxy=$HTTP_PROXY https_proxy=$HTTPS_PROXY all_proxy=$ALL_PROXY
unset GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM

pin() {
  opam pin add --no-action "$1" "$CURRENT/bundle/pins/$2"
}

run_closed_scan() {
  executable=$1
  config=$2
  target=$3
  stdout=$4
  stderr=$5
  env -i HOME="$CURRENT/smoke-home" TMPDIR="$CURRENT/smoke-tmp" PATH="$CURRENT/empty-path" LC_ALL=C TZ=UTC \
    "$executable" scan \
      --experimental \
      --oss-only \
      --metrics=off \
      --disable-version-check \
      --strict \
      --error \
      --json \
      --quiet \
      --no-git-ignore \
      --x-ignore-semgrepignore-files \
      --jobs=1 \
      --timeout=30 \
      --timeout-threshold=1 \
      --max-target-bytes=8388608 \
      --config "$config" \
      "$target" > "$stdout" 2> "$stderr"
}

verify_smoke_results() {
  "$NODE" -e '
    const fs = require("node:fs");
    const [path, expectedText] = process.argv.slice(1);
    const expected = Number(expectedText);
    const report = JSON.parse(fs.readFileSync(path, "utf8"));
    if (!Array.isArray(report.results) || report.results.length !== expected) process.exit(1);
    if (Array.isArray(report.errors) && report.errors.length !== 0) process.exit(1);
    if (expected === 1 && report.results[0].check_id !== "context-relay-smoke") process.exit(1);
  ' "$1" "$2" || die "closed scan result count mismatch"
}

build_once() {
  label=$1
  CURRENT="$WORK_ROOT/current"
  rm -rf "$CURRENT"
  mkdir -p "$CURRENT/bundle" "$CURRENT/home" "$CURRENT/tmp"
  tar -xf "$SOURCE_BUNDLE" -C "$CURRENT/bundle"
  "$NODE" "$WORKSPACE/scripts/semgrep-source-bundle.mjs" --materialize-links "$CURRENT/bundle" >/dev/null
  PROJECT="$CURRENT/bundle/sources/semgrep"
  test -f "$PROJECT/Makefile" || die "Semgrep source is missing"
  test "$SOURCE_REVISION" = bd614accba811b407ae5c9ec6f1eecd3bdc29911

  TS_DOWNLOADS="$PROJECT/libs/ocaml-tree-sitter-core/downloads"
  mkdir -p "$TS_DOWNLOADS"
  tar -xf "$CURRENT/bundle/opam-repository/cache/sha256/${TREE_SITTER_SHA%${TREE_SITTER_SHA#??}}/$TREE_SITTER_SHA" -C "$TS_DOWNLOADS"
  test -d "$TS_DOWNLOADS/tree-sitter-0.22.6" || die "tree-sitter source did not unpack as expected"

  export HOME="$CURRENT/home" TMPDIR="$CURRENT/tmp" OPAMROOT="$CURRENT/opam"
  opam init --bare --disable-sandboxing --no-setup default "$CURRENT/bundle/opam-repository"
  ARCHIVE_MIRROR="file://$CURRENT/bundle/opam-repository/cache"
  opam option --global "archive-mirrors=[\"$ARCHIVE_MIRROR\"]"
  opam switch create "$CURRENT/switch" --empty
  eval "$(opam env --switch "$CURRENT/switch" --set-switch)"

  pin ocaml-variants.5.3.0 3499e5708b0637c12d24d973dd103406a32b8fe8
  opam install --update-invariant ocaml-variants.5.3.0 ocaml-option-flambda
  pin pcre2.dev 4e0a44486bb518b7a24ca11286c4b03a8d51e17e
  pin tree-sitter.dev c4baff8d83b2e1f83f247acb11d0c9dafa5e48f7
  for package in testo.dev testo-util.dev testo-diff.dev testo-lwt.dev; do pin "$package" df18ea541c75c9acf75923218586c5ffe8915a04; done
  pin obackward.dev e1c16766976b4fadd97097b96f96666e8e1cb98c
  pin semgrep-interfaces.dev 7e509db48c700cae49fe0372e2aa0410fa86d867
  for package in pyro-caml-instruments.dev pyro-caml-ppx.dev; do pin "$package" ef59d6c39085079bb7d2ea76b3d4c7a7d4ec27d9; done
  for package in opentelemetry.dev opentelemetry-client-ocurl.dev opentelemetry-client-cohttp-eio.dev opentelemetry-logs.dev; do pin "$package" 6cfa5f16d85ac65b602f732469b667bac4aca5ac; done
  pin memtrace.dev a88470c3de884182503ba5fcd4729e281e544731

  cd "$PROJECT"
  ./scripts/pick-lockfile.sh --strict semgrep.opam
  (
    cd libs/ocaml-tree-sitter-core
    ./configure
    ./scripts/install-tree-sitter-lib
  )
  OPAMIGNOREPINDEPENDS=true opam install --locked --update-invariant --deps-only ./semgrep.opam ./dev/required.opam
  ./scripts/validate-compiler-sha.sh
  opam exec -- make core

  EXECUTABLE="$PROJECT/_build/install/default/bin/osemgrep"
  test -x "$EXECUTABLE" || die "osemgrep was not built"
  DESTINATION="$OUTPUT_ROOT/$label"
  EVIDENCE="$OUTPUT_ROOT/$label-evidence"
  mkdir -p "$DESTINATION" "$EVIDENCE"
  cp "$EXECUTABLE" "$DESTINATION/osemgrep"
  OTOOL_OUTPUT="$CURRENT/otool-L.txt"
  if ! otool -L "$DESTINATION/osemgrep" > "$OTOOL_OUTPUT"; then
    die "otool runtime dependency inventory failed"
  fi
  awk 'NR > 1 {print $1}' "$OTOOL_OUTPUT" > "$EVIDENCE/runtime-dependencies.txt"
  rm "$OTOOL_OUTPUT"
  if grep -Eiq '(^|/)lib?python|python[0-9.]*\.dylib' "$EVIDENCE/runtime-dependencies.txt"; then
    die "Python runtime dependency detected"
  fi
  while IFS= read -r dependency; do
    case "$dependency" in
      /usr/lib/*|/System/Library/*) ;;
      '') ;;
      *) die "unpackaged non-system runtime dependency: $dependency" ;;
    esac
  done < "$EVIDENCE/runtime-dependencies.txt"
  SMOKE_FIXTURES="$CURRENT/smoke-fixtures"
  mkdir -p "$CURRENT/empty-path" "$CURRENT/smoke-home" "$CURRENT/smoke-tmp" "$SMOKE_FIXTURES"
  printf '%s\n' \
    'rules:' \
    '  - id: context-relay-smoke' \
    '    languages: [generic]' \
    '    severity: ERROR' \
    '    message: Context Relay native smoke finding' \
    '    pattern: context-relay-finding' > "$SMOKE_FIXTURES/rule.yml"
  printf '%s\n' 'rules: [' > "$SMOKE_FIXTURES/invalid-rule.yml"
  printf '%s\n' 'clean target' > "$SMOKE_FIXTURES/clean.txt"
  printf '%s\n' 'context-relay-finding' > "$SMOKE_FIXTURES/finding.txt"
  env -i HOME="$CURRENT/smoke-home" TMPDIR="$CURRENT/smoke-tmp" PATH="$CURRENT/empty-path" \
    "$DESTINATION/osemgrep" --version > "$EVIDENCE/version.txt"
  if ! (cd "$SMOKE_FIXTURES" && run_closed_scan "$DESTINATION/osemgrep" rule.yml clean.txt \
      "$EVIDENCE/clean.json" "$EVIDENCE/clean.stderr"); then
    die "closed clean scan failed"
  fi
  verify_smoke_results "$EVIDENCE/clean.json" 0
  if (cd "$SMOKE_FIXTURES" && run_closed_scan "$DESTINATION/osemgrep" rule.yml finding.txt \
      "$EVIDENCE/finding.json" "$EVIDENCE/finding.stderr"); then
    die "closed finding scan unexpectedly returned zero with --error"
  else
    FINDING_STATUS=$?
  fi
  test "$FINDING_STATUS" -eq 1 || die "closed finding scan returned an unexpected status"
  verify_smoke_results "$EVIDENCE/finding.json" 1
  if (cd "$SMOKE_FIXTURES" && run_closed_scan "$DESTINATION/osemgrep" invalid-rule.yml clean.txt \
      "$EVIDENCE/invalid.json" "$EVIDENCE/invalid.stderr"); then
    die "invalid rule unexpectedly passed"
  else
    INVALID_STATUS=$?
  fi
  if test "$INVALID_STATUS" -eq 0 || test "$INVALID_STATUS" -eq 1; then
    die "invalid rule did not produce a distinct config failure"
  fi
  if ! grep -Eiq 'invalid|error|parse|config|yaml' "$EVIDENCE/invalid.json" "$EVIDENCE/invalid.stderr"; then
    die "invalid rule evidence lacks a parse or config error"
  fi
  (
    cd "$DESTINATION"
    find . -type f ! -name MANIFEST.sha256 -print | sed 's#^\./##' | LC_ALL=C sort | while IFS= read -r file; do
      shasum -a 256 "$file"
    done > "$EVIDENCE/MANIFEST.sha256"
  )
}

build_once "$BUILD_LABEL"
printf '%s\n' \
  '{"mechanism":"macos-sandbox-exec-network-deny","probe":"hostile-outbound-tcp-denied-with-eperm-or-eacces","schemaVersion":1}' \
  > "$OUTPUT_ROOT/$BUILD_LABEL.offline-egress.v1.json"
printf '%s\n' "macOS arm64 public-source $BUILD_LABEL completed with kernel-enforced network denial."
