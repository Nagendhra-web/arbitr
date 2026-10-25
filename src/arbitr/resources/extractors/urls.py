"""URLs and database connection strings.

A resource URI keeps the scheme, host, port and path. User names, passwords,
fragments and query strings are dropped (except the location parameters of a
database URL, such as ``host``), because they often hold secrets and
policies match on where a call goes, not on its parameters.

Example:
    >>> [(r.kind, r.uri) for r in url_refs("postgres://app:pw@db.prod:5432/orders?ssl=1")]
    [('database', 'postgres://db.prod:5432/orders')]
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from arbitr.resources.base import make_ref

if TYPE_CHECKING:
    from arbitr.core.spec import ResourceRef

DATABASE_SCHEMES: Final = frozenset(
    {
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "sqlite",
        "mongodb",
        "mongodb+srv",
        "redis",
        "rediss",
        "mssql",
        "sqlserver",
        "oracle",
        "snowflake",
        "clickhouse",
        "cockroachdb",
        "cassandra",
        "neo4j",
        "bolt",
        "duckdb",
        "bigquery",
        "redshift",
    }
)
_GITHUB_HOSTS: Final = frozenset({"github.com", "www.github.com"})
_DSN_LOCATION: Final = frozenset(
    {"host", "hostaddr", "port", "service", "dbname", "database", "server", "address"}
)


def url_refs(raw: str) -> list[ResourceRef]:
    """Resources for a URL: a ``url`` or ``database``, plus a ``github_repo`` if any."""
    try:
        parts = urlsplit(raw.strip())
        port = parts.port
    except ValueError:
        return []
    scheme = parts.scheme.lower()
    if not scheme or not (parts.netloc or parts.path):
        return []
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    netloc = host + (f":{port}" if port is not None else "")
    base_scheme = scheme if scheme in DATABASE_SCHEMES else scheme.split("+", 1)[0]
    kind = "database" if base_scheme in DATABASE_SCHEMES else "url"
    if kind == "database":
        uri = f"{scheme}://{netloc}{parts.path}"
        # Drivers such as libpq also take the host from the query string.
        kept = [(k, v) for k, v in parse_qsl(parts.query) if k.lower() in _DSN_LOCATION]
        if kept:
            uri += "?" + "&".join(f"{k}={v}" for k, v in sorted(kept))
        # A host in the query string wins over the one in the URL, so it gets its own resource.
        query_hosts = [
            h.strip().lower()
            for k, v in kept
            if k.lower() in ("host", "hostaddr")
            for h in v.split(",")
        ]
        # libpq pairs a comma list of ports with the hosts by position.
        ports = [p.strip() for k, v in kept if k.lower() == "port" for p in v.split(",")]
        if not ports and port is not None:
            ports = [str(port)]
        refs = [make_ref(kind, uri)]
        for i, h in enumerate(query_hosts):
            if not h or h.startswith("/"):
                continue
            host_port = ports[i] if i < len(ports) else (ports[-1] if ports else "")
            suffix = f":{host_port}" if host_port else ""
            refs.append(make_ref(kind, f"{scheme}://{h}{suffix}{parts.path}"))
        return refs
    uri = urlunsplit((scheme, netloc, parts.path, "", ""))
    refs = [make_ref(kind, uri)]
    segments = [s for s in parts.path.split("/") if s]
    if parts.hostname in _GITHUB_HOSTS and len(segments) >= 2:  # noqa: PLR2004 - owner/repo
        repo = segments[1].removesuffix(".git")
        refs.append(make_ref("github_repo", f"{segments[0]}/{repo}".lower()))
    return refs
