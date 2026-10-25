#!/usr/bin/env bash
# Run `make ci` inside the pinned CI image (make ci-docker).
# The repository, including .git, is copied into the image rather than bind
# mounted, so the run is the same from a Windows, macOS or Linux host and from
# inside act. Logs are copied back to ci-logs/ afterwards.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=lib/env.sh
. scripts/lib/env.sh
# Stop Git Bash on Windows from rewriting container paths such as /var/run/docker.sock.
export MSYS_NO_PATHCONV=1

image="${ARBITR_CI_IMAGE:-arbitr-ci:local}"
name="arbitr-ci-run-$$"

docker info >/dev/null 2>&1 || { echo "Docker is not running. Start Docker and rerun." >&2; exit 1; }

docker build -f deploy/Dockerfile.ci -t "$image" .
digest="$(docker image inspect --format '{{.Id}}' "$image")"

set +e
docker run --name "$name" \
  --add-host=host.docker.internal:host-gateway \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e ARBITR_CI_IMAGE_DIGEST="$digest" \
  -e ARBITR_SIM_SEEDS="${ARBITR_SIM_SEEDS:-2000}" \
  -e ARBITR_TLC_MODEL="${ARBITR_TLC_MODEL:-small}" \
  "$image" make ci
rc=$?
set -e

mkdir -p ci-logs
docker cp "$name:/repo/ci-logs/." ci-logs/ >/dev/null 2>&1 || echo "warning: could not copy ci-logs out of the container" >&2
docker rm "$name" >/dev/null
echo "make ci-docker finished with exit code $rc (image $digest)."
exit "$rc"
