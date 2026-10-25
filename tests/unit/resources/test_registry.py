"""The resource registry: built-in extraction from args, policy tags, effects."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from arbitr.core.errors import ArbitrError, ResourceError
from arbitr.core.spec import ResourceRef, ToolSpec
from arbitr.policy.engine import GateInput, decide
from arbitr.policy.schema import load_policy
from arbitr.resources.registry import classify, extract, path_glob_match, resolve

POLICY = load_policy(
    """
version: 1
resources:
  - id: prod-db
    match: { kind: database, uri_glob: "postgres://*prod*" }
    tags: [production, critical]
  - id: backups
    match: { kind: path, glob: "/var/backups/**" }
    tags: [backup, critical]
  - id: var
    match: { kind: path, glob: "/var/**" }
    tags: [system]
  - id: public-repos
    match: { kind: github_repo, attrs: { visibility: public } }
    tags: [public]
rules:
  - id: no-destroy-critical
    when: { effect: destructive, resource_tags_any: [critical] }
    then: deny
    reason: Destroying critical resources is not allowed.
  - id: var-is-watched
    when: { resource_ids_any: [var] }
    then: require_approval
    reason: Changes under /var need a human.
"""
)

WRITE = ToolSpec(name="db.exec", effect="write")


def refs(args: dict[str, object], spec: ToolSpec = WRITE) -> list[tuple[str, str]]:
    return [(r.kind, r.uri) for r in extract(spec, args).resources]


# ---------------------------------------------------------------- extraction by key


@pytest.mark.parametrize(
    ("args", "effect"),
    [
        ({"sql": "DROP TABLE x"}, "destructive"),
        ({"query": "SELECT 1"}, "read"),
        ({"statement": "DELETE FROM t WHERE id = 1"}, "write"),
        ({"command": "rm -rf /"}, "destructive"),
        ({"cmd": ["rm", "-rf", "/"]}, "destructive"),
        ({"commands": ["ls", "rm -rf /"]}, "destructive"),
        ({"options": {"shell_command": "git push --force"}}, "destructive"),
        ({"steps": [{"sql": "TRUNCATE t"}]}, "destructive"),
        ({"text": "DROP TABLE x"}, None),
        ({"path": "/srv/x"}, None),
        ({}, None),
    ],
)
def test_effect_by_argument_name(args: dict[str, object], effect: str | None) -> None:
    assert extract(WRITE, args).effect == effect


def test_paths_are_normalized() -> None:
    assert refs({"path": "/var/backups/../log/x"}) == [("path", "/var/log/x")]
    assert refs({"files": ["a.txt", "C:\\data\\b.txt"]}) == [
        ("path", "a.txt"),
        ("path", "c:/data/b.txt"),
    ]


def test_urls_lose_credentials_queries_and_fragments() -> None:
    assert refs({"url": "https://bob:pw@Example.com/a?token=x#f"}) == [
        ("url", "https://example.com/a")
    ]


def test_database_urls_and_names() -> None:
    assert refs({"dsn": "postgres://u:p@prod-db:5432/orders?sslmode=require"}) == [
        ("database", "postgres://prod-db:5432/orders")
    ]
    assert refs({"database": "orders"}) == [("database", "orders")]


def test_github_repos() -> None:
    assert refs({"repo": "Owner/Repo"}) == [("github_repo", "owner/repo")]
    assert refs({"owner": "o", "repo": "r"}) == [("github_repo", "o/r")]
    assert refs({"url": "https://github.com/o/r/pull/1"}) == [
        ("github_repo", "o/r"),
        ("url", "https://github.com/o/r/pull/1"),
    ]


def test_email_recipients() -> None:
    result = extract(WRITE, {"to": "Bob <Bob@Example.com>, carol@x.org", "cc": ["d@y.io"]})
    assert [(r.uri, r.attrs) for r in result.resources] == [
        ("bob@example.com", {"domain": "example.com"}),
        ("carol@x.org", {"domain": "x.org"}),
        ("d@y.io", {"domain": "y.io"}),
    ]
    assert all(r.kind == "email" for r in result.resources)
    assert refs({"to": "not an address"}) == [("email", "unparsed")]


def test_resources_are_deduplicated_and_sorted() -> None:
    assert refs({"path": "/b", "paths": ["/a", "/b"]}) == [("path", "/a"), ("path", "/b")]


def test_huge_arguments_fail_safe() -> None:
    result = extract(WRITE, {"items": [{"x": i} for i in range(20_000)]})
    assert result.effect == "destructive"
    assert "args:too-large" in result.labels


# ---------------------------------------------------------------- custom extractors


def test_a_custom_extractor_replaces_built_in_resources() -> None:
    spec = ToolSpec(name="t", effect="write", resource_extractor="custom_extractors:tables")
    result = extract(spec, {"table": "orders", "path": "/srv/x", "sql": "DROP TABLE orders"})
    assert [(r.kind, r.uri) for r in result.resources] == [("table", "orders")]
    # Effects are still classified, so a custom extractor cannot hide a DROP.
    assert result.effect == "destructive"


@pytest.mark.parametrize(
    "path",
    ["custom_extractors:broken", "custom_extractors:wrong_type", "no_such_module:fn"],
)
def test_a_failing_custom_extractor_raises(path: str) -> None:
    spec = ToolSpec(name="t", effect="write", resource_extractor=path)
    with pytest.raises(ResourceError):
        extract(spec, {})
    assert issubclass(ResourceError, ArbitrError)


# ---------------------------------------------------------------- policy tags


def resolved(*items: ResourceRef) -> list[tuple[str | None, str, frozenset[str]]]:
    return [(r.id, r.uri, r.tags) for r in resolve(POLICY, items)]


def test_uri_globs_match_any_characters() -> None:
    ref = ResourceRef(kind="database", uri="postgres://db.prod.internal/orders")
    assert resolved(ref) == [
        ("prod-db", ref.uri, frozenset({"production", "critical"})),
    ]


def test_path_globs_respect_separators() -> None:
    assert path_glob_match("/var/backups/**", "/var/backups")
    assert path_glob_match("/var/backups/**", "/var/backups/a/b")
    assert not path_glob_match("/var/backups/**", "/var/backupsX")
    assert path_glob_match("/srv/*/logs", "/srv/a/logs")
    assert not path_glob_match("/srv/*/logs", "/srv/a/b/logs")
    assert path_glob_match("/srv/**/logs", "/srv/a/b/logs")
    assert path_glob_match("/srv/app?.log", "/srv/app1.log")
    assert not path_glob_match("/srv/app?.log", "/srv/app/.log")


def test_paths_are_normalized_before_matching() -> None:
    sneaky = ResourceRef(kind="path", uri="/srv/../var/backups/db")
    (match,) = resolve(POLICY, [sneaky])
    assert match.uri == "/var/backups/db"
    assert "critical" in match.tags


def test_every_matching_definition_counts() -> None:
    (match,) = resolve(POLICY, [ResourceRef(kind="path", uri="/var/backups/db")])
    assert match.id == "backups"
    assert match.ids == frozenset({"backups", "var"})
    assert match.tags == frozenset({"backup", "critical", "system"})


def test_attrs_must_all_match() -> None:
    public = ResourceRef(kind="github_repo", uri="o/r", attrs={"visibility": "public"})
    private = ResourceRef(kind="github_repo", uri="o/r", attrs={"visibility": "private"})
    assert resolved(public)[0][0] == "public-repos"
    assert resolved(private) == [(None, "o/r", frozenset())]


# ---------------------------------------------------------------- end to end


def gate(tool: str, effect: str, args: dict[str, object]) -> GateInput:
    spec = ToolSpec(name=tool, effect=effect)  # type: ignore[arg-type]
    c = classify(spec, args, POLICY)
    return GateInput(
        tool=tool,
        effect=c.effect,
        args=args,
        principal="p",
        agent_id="a",
        run_id="r",
        now=datetime(2026, 10, 25, tzinfo=UTC),
        resources=c.resources,
    )


def test_destructive_shell_on_backups_is_denied() -> None:
    d = decide(gate("shell.run", "write", {"command": "rm -rf /var/backups/db"}), POLICY, {})
    assert (d.outcome, d.rule_id) == ("deny", "no-destroy-critical")


def test_resource_ids_any_sees_every_matching_definition() -> None:
    d = decide(gate("fs.write", "write", {"path": "/var/backups/x"}), POLICY, {})
    assert (d.outcome, d.rule_id) == ("require_approval", "var-is-watched")


def test_effects_are_raised_never_lowered() -> None:
    assert classify(WRITE, {"sql": "DROP TABLE t"}, POLICY).effect == "destructive"
    spec = ToolSpec(name="db.admin", effect="destructive")
    assert classify(spec, {"sql": "SELECT 1"}, POLICY).effect == "destructive"
    assert classify(WRITE, {"sql": "SELECT 1"}, POLICY).effect == "write"


# ---------------------------------------------------------------- hardening


def test_resources_differing_only_by_attrs_are_all_kept() -> None:
    plain = ResourceRef(kind="github_repo", uri="o/r")
    public = ResourceRef(kind="github_repo", uri="o/r", attrs={"visibility": "public"})
    for order in ([plain, public], [public, plain]):
        assert {r.id for r in resolve(POLICY, order)} == {None, "public-repos"}


@pytest.mark.parametrize(
    "path",
    ["/var", "/", "/var/", "/var/backups/*", "/var/back*", "/var/backups/db/*.sql", "/v?r"],
)
def test_a_path_that_covers_a_protected_area_gets_its_tags(path: str) -> None:
    (match,) = resolve(POLICY, [ResourceRef(kind="path", uri=path)])
    assert "critical" in match.tags, path


def test_a_sibling_path_does_not_get_the_tags() -> None:
    (match,) = resolve(POLICY, [ResourceRef(kind="path", uri="/srv/app")])
    assert match.tags == frozenset()


@pytest.mark.parametrize("path", ["build", "./x", "~/x", "$HOME/x", "${DATA}/db"])
def test_unresolved_paths_are_tagged(path: str) -> None:
    (match,) = resolve(POLICY, [ResourceRef(kind="path", uri=path)])
    assert "arbitr:unresolved-path" in match.tags


def test_windows_paths_match_without_case() -> None:
    policy = load_policy(
        "version: 1\nresources:\n  - id: data\n    match: { kind: path, glob: 'C:/Data/**' }\n"
        "    tags: [critical]\n"
    )
    (match,) = resolve(policy, [ResourceRef(kind="path", uri="c:\\DATA\\db.sqlite")])
    assert match.tags == frozenset({"critical"})


def test_destroying_a_parent_of_backups_is_denied() -> None:
    d = decide(gate("shell.run", "write", {"command": "rm -rf /var"}), POLICY, {})
    assert (d.outcome, d.rule_id) == ("deny", "no-destroy-critical")


def test_database_hosts_in_query_strings_are_kept() -> None:
    assert refs({"dsn": "postgres:///orders?host=prod-db&password=pw&sslmode=require"}) == [
        ("database", "postgres:///orders?host=prod-db"),
        ("database", "postgres://prod-db/orders"),
    ]
    ref = ResourceRef(kind="database", uri="postgres:///orders?host=prod-db")
    assert resolved(ref)[0][0] == "prod-db"


def test_key_value_dsns_are_parsed() -> None:
    assert refs({"dsn": "host=prod-db port=5432 dbname=orders user=app password=pw"}) == [
        ("database", "postgresql://prod-db:5432/orders")
    ]


def test_unparseable_recipients_fail_closed() -> None:
    result = extract(WRITE, {"to": "bob@example.com, not an address"})
    assert [(r.uri, r.attrs) for r in result.resources] == [
        ("bob@example.com", {"domain": "example.com"}),
        ("unparsed", {"domain": "unparsed"}),
    ]


@pytest.mark.parametrize("path", ["/var/{backups,x}/db", "/var/{a,b}"])
def test_brace_paths_are_judged_by_their_literal_folder(path: str) -> None:
    (match,) = resolve(POLICY, [ResourceRef(kind="path", uri=path)])
    assert "critical" in match.tags


def test_windows_device_prefixes_and_trailing_dots_are_normalized() -> None:
    assert refs({"path": r"\\?\C:\Data\x"}) == [("path", "c:/data/x")]
    assert refs({"path": r"\\.\C:\Data\x"}) == [("path", "c:/data/x")]
    assert refs({"path": r"\\?\UNC\server\share\x"}) == [("path", "//server/share/x")]
    assert refs({"path": "C:\\Data. \\x"}) == [("path", "c:/data/x")]


def test_every_database_host_becomes_a_resource() -> None:
    assert refs({"dsn": "postgres://localhost/orders?host=prod-db"}) == [
        ("database", "postgres://localhost/orders?host=prod-db"),
        ("database", "postgres://prod-db/orders"),
    ]
    assert refs({"dsn": "host=safe hostaddr=10.0.0.9 dbname=orders"}) == [
        ("database", "postgresql://10.0.0.9/orders"),
        ("database", "postgresql://safe/orders"),
    ]


def test_several_addresses_in_one_part_are_all_kept_and_flagged() -> None:
    result = extract(WRITE, {"to": "bob@example.com evil@attacker.example"})
    assert [r.uri for r in result.resources] == [
        "bob@example.com",
        "evil@attacker.example",
        "unparsed",
    ]


def test_query_hosts_are_lower_cased_and_keep_the_query_port() -> None:
    found = refs({"dsn": "postgres://localhost/db?host=PROD-DB&port=6543"})
    assert ("database", "postgres://prod-db:6543/db") in found


def test_leading_double_star_globs_do_not_tag_every_ancestor() -> None:
    policy = load_policy(
        "version: 1\nresources:\n  - id: ci\n"
        "    match: { kind: path, glob: '**/.github/workflows/**' }\n"
        "    tags: [ci-config]\n"
    )
    tags = {
        r.uri: r.tags
        for r in resolve(
            policy,
            [
                ResourceRef(kind="path", uri="/srv/repo/.github/workflows/ci.yml"),
                ResourceRef(kind="path", uri="repo/.github/workflows/ci.yml"),
                ResourceRef(kind="path", uri="/srv/repo/.github"),
                ResourceRef(kind="path", uri=".github"),
                ResourceRef(kind="path", uri="/srv/repo"),
                ResourceRef(kind="path", uri="/"),
            ],
        )
    }
    assert "ci-config" in tags["/srv/repo/.github/workflows/ci.yml"]
    assert "ci-config" in tags["repo/.github/workflows/ci.yml"]
    assert "ci-config" in tags["/srv/repo/.github"]
    assert "ci-config" in tags[".github"]
    assert "ci-config" not in tags["/srv/repo"]
    assert "ci-config" not in tags["/"]


def test_libpq_ports_pair_with_hosts() -> None:
    found = refs({"dsn": "postgres:///db?host=a-prod,b-prod&port=5432,6543"})
    assert ("database", "postgres://a-prod:5432/db") in found
    assert ("database", "postgres://b-prod:6543/db") in found
