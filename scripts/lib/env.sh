#!/usr/bin/env bash
# Shared environment for the local CI scripts. Source this file, do not run it.
#
# On Windows hosts, tools installed by Docker Desktop, winget and Temurin are
# often missing from PATH in non-login shells. Add their standard locations so
# every script finds the same binaries. On Linux and macOS this is a no-op.

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    _arbitr_add_path() { [ -d "$1" ] && case ":$PATH:" in *":$1:"*) ;; *) PATH="$PATH:$1" ;; esac; }
    _arbitr_add_path "/c/Program Files/Docker/Docker/resources/bin"
    for _d in "/c/Program Files/Eclipse Adoptium"/*/bin; do _arbitr_add_path "$_d"; done
    if [ -n "${LOCALAPPDATA:-}" ]; then
      _winget="$(cygpath -u "$LOCALAPPDATA")/Microsoft/WinGet"
      _arbitr_add_path "$_winget/Links"
      for _d in "$_winget"/Packages/*/; do _arbitr_add_path "${_d%/}"; done
    fi
    export PATH
    unset _d _winget
    ;;
esac

# `docker compose` (plugin) when available, otherwise the standalone binary.
compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  else
    docker-compose "$@"
  fi
}

# Postgres used by the test suite. Inside a container (make ci-docker, act)
# the database published by compose is reachable through the host gateway.
if [ -z "${ARBITR_PG_HOST:-}" ]; then
  # 127.0.0.1, not localhost: localhost may resolve to ::1 first, where nothing listens.
  if [ -f /.dockerenv ]; then ARBITR_PG_HOST=host.docker.internal; else ARBITR_PG_HOST=127.0.0.1; fi
fi
export ARBITR_PG_HOST
export ARBITR_PG_PORT="${ARBITR_PG_PORT:-55432}"
export ARBITR_TEST_POSTGRES_URL="${ARBITR_TEST_POSTGRES_URL:-postgresql://arbitr:arbitr@${ARBITR_PG_HOST}:${ARBITR_PG_PORT}/arbitr_test?connect_timeout=10}"
