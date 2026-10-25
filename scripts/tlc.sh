#!/usr/bin/env bash
# Run the TLC model checker on every model in formal/.
#   scripts/tlc.sh small   models in formal/*.small.cfg (make ci, under 2 minutes)
#   scripts/tlc.sh large   models in formal/*.large.cfg (make release-check)
# tla2tools.jar is downloaded once, pinned by version and sha256.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

size="${1:-small}"
TLA_VERSION="1.7.4"
TLA_SHA256="936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
jar="${ARBITR_TLA_JAR:-.tools/tla2tools-${TLA_VERSION}.jar}"

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

if [ ! -f "$jar" ]; then
  mkdir -p "$(dirname "$jar")"
  echo "Downloading tla2tools ${TLA_VERSION}."
  curl -sSfL -o "$jar" "https://github.com/tlaplus/tlaplus/releases/download/v${TLA_VERSION}/tla2tools.jar"
fi
if [ "$(sha256 "$jar")" != "$TLA_SHA256" ]; then
  echo "tla2tools.jar checksum mismatch at $jar. Delete it and rerun." >&2
  exit 1
fi

# Absolute jar path, in the form java expects on this OS (TLC runs from formal/).
jar_abs="$(cd "$(dirname "$jar")" && pwd)/$(basename "$jar")"
command -v cygpath >/dev/null 2>&1 && jar_abs="$(cygpath -m "$jar_abs")"

# The small model must finish in under 2 minutes, so enforce it.
limit=()
if [ "$size" = "small" ]; then
  command -v timeout >/dev/null || { echo "timeout(1) is required for the small model." >&2; exit 1; }
  limit=(timeout 120)
fi

shopt -s nullglob
cfgs=(formal/*."${size}".cfg)
if [ "${#cfgs[@]}" -eq 0 ]; then
  echo "No formal/*.${size}.cfg models found." >&2
  exit 1
fi

for cfg in "${cfgs[@]}"; do
  base="$(basename "$cfg" ".${size}.cfg")"
  echo "-- TLC ${base} (${size})"
  meta=".tools/tlc-states/${base}-${size}"
  rm -rf "$meta"
  # Deadlock checking stays on: the model stutters explicitly once every
  # intent is at rest (Done in the spec), so any other stuck state is a bug.
  (cd formal && "${limit[@]}" java -XX:+UseParallelGC -cp "$jar_abs" tlc2.TLC \
    -config "$(basename "$cfg")" -workers auto -cleanup \
    -metadir "../$meta" "${base}.tla")
done
