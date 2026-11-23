#!/usr/bin/env bash
# Runs the conformance suite of the pinned AXT release against this library's adapter
# (AXT spec/conformance.md, sections 6 and 7). The archive is checked by its SHA-256 and
# its attestation before anything in it runs. Needs curl, gh (logged in, or GH_TOKEN set),
# uv, python3 >= 3.11, cargo and rustup (with the rustfmt of rust-toolchain.toml).
#
# Arguments are passed to the runner, e.g. --category encoding. Locally, AXT_PYTHON names a
# Python that has the suite's dependencies (pyproject.toml of the release) in place of uv, and
# AXT_SKIP_ATTESTATION=1 skips the attestation where gh has no `attestation` command; the
# SHA-256 is checked either way. CI sets neither.
set -euo pipefail

AXT_VERSION=0.2.0
AXT_SHA256=76a4a77a8ba7f2b31a3c59481b8e2dd67cbeb0fad03448461bde6e0429c6c0c7
BASE=https://github.com/paxel/axt/releases/download/v$AXT_VERSION
ARCHIVE=axt-$AXT_VERSION.tar.gz
BUNDLE=axt-v$AXT_VERSION-provenance.sigstore.json

root=$(cd "$(dirname "$0")/.." && pwd)
work=${AXT_WORK:-$root/build/conformance}
rm -rf "$work"
mkdir -p "$work"
cd "$work"

curl --proto =https --proto-redir =https -fsSL -o "$ARCHIVE" "$BASE/$ARCHIVE"
curl --proto =https --proto-redir =https -fsSL -o "$BUNDLE" "$BASE/$BUNDLE"
echo "$AXT_SHA256  $ARCHIVE" | sha256sum --check --strict
if [ "${AXT_SKIP_ATTESTATION:-}" = "1" ]; then
  echo "The attestation was not checked (AXT_SKIP_ATTESTATION=1); the SHA-256 was."
else
  # The release attests through the reusable provenance workflow of paxel/gates, so that
  # workflow is the signer; the source is paxel/axt at the release tag.
  gh attestation verify "$ARCHIVE" --bundle "$BUNDLE" --repo paxel/axt \
    --signer-workflow paxel/gates/.github/workflows/provenance.yml \
    --source-ref "refs/tags/v$AXT_VERSION"
fi

mkdir suite
tar -xzf "$ARCHIVE" -C suite --strip-components=1
if [ -z "${AXT_PYTHON:-}" ]; then
  (cd suite && uv sync --frozen --no-dev --no-build)
fi

# The example types ship generated (crates/axt-protocol/src/examples.rs): generated again
# from the release's descriptions, they must not differ. The generator is built and its
# rustfmt found in "$root", so that both are of the toolchain of rust-toolchain.toml.
(cd "$root" && cargo build --locked --release -p axt-protocol-generate)
rustfmt=$(cd "$root" && rustup which rustfmt)
(cd suite && RUSTFMT="$rustfmt" "$root/target/release/axt-protocol-generate" \
  types/axt/example/v1/*.1.json -o "$work/examples.rs")
diff -u "$root/crates/axt-protocol/src/examples.rs" "$work/examples.rs"

(cd "$root" && cargo build --locked --release -p axt-conformance-adapter)
adapter="$root/target/release/axt-conformance-adapter"

# The runner fails when the adapter declares no category; until the first category is
# implemented, the check of the archive and the adapter's hello are the whole job.
hello=$(echo '{"id": "hello", "op": "hello", "input": {"format": 1}}' | "$adapter")
if python3 -c 'import json, sys; sys.exit(0 if json.loads(sys.argv[1])["output"]["categories"] else 1)' "$hello"; then
  cd suite
  if [ -n "${AXT_PYTHON:-}" ]; then
    "$AXT_PYTHON" -I conformance/run.py "$@" -- "$adapter"
  else
    uv run --frozen --no-dev python3 conformance/run.py "$@" -- "$adapter"
  fi
else
  echo "The adapter implements no category yet; the suite was checked but not run: $hello"
fi
