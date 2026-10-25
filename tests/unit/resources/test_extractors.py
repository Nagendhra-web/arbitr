"""SQL and shell extractors: the classification tables, resources and labels."""

from __future__ import annotations

import shlex
import time

import pytest

from arbitr.resources.extractors import sql as sql_module
from arbitr.resources.extractors.shell import classify_shell
from arbitr.resources.extractors.sql import classify_sql
from extractor_cases import SHELL_CASES, SQL_CASES


@pytest.fixture(params=["parser", "fallback"])
def sql_mode(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Run SQL tests with sqlglot and with the token fallback alone."""
    if request.param == "fallback":
        monkeypatch.setattr(sql_module, "_PARSER", False)
    else:
        assert sql_module._PARSER, "sqlglot is installed in the dev environment"
    return str(request.param)


def test_the_tables_are_large_enough() -> None:
    assert len(SQL_CASES) >= 100
    assert len(SHELL_CASES) >= 100
    assert len({t for t, _ in SQL_CASES}) == len(SQL_CASES)
    assert len({c for c, _ in SHELL_CASES}) == len(SHELL_CASES)


@pytest.mark.parametrize(("text", "expected"), SQL_CASES)
def test_sql_table(text: str, expected: str | None, sql_mode: str) -> None:
    assert classify_sql(text).effect == expected


@pytest.mark.parametrize(("command", "expected"), SHELL_CASES)
def test_shell_table(command: str, expected: str | None) -> None:
    assert classify_shell(command).effect == expected


# ---------------------------------------------------------------- SQL resources


def _uris(text: str, kind: str = "table") -> list[str]:
    return [r.uri for r in classify_sql(text).resources if r.kind == kind]


@pytest.mark.parametrize(
    ("text", "tables"),
    [
        ("DELETE FROM App.Users WHERE id = 1", ["app.users"]),
        ('DROP TABLE "Users"', ["Users"]),
        ("SELECT * FROM a JOIN b ON a.x = b.x", ["a", "b"]),
        ("WITH x AS (SELECT * FROM a) SELECT * FROM x", ["a"]),
        ("INSERT INTO log SELECT * FROM events", ["events", "log"]),
        ("TRUNCATE a, b", ["a", "b"]),
        ("UPDATE t SET a = 1 WHERE id = 2", ["t"]),
        ("SELECT 1", []),
    ],
)
def test_sql_tables(text: str, tables: list[str], sql_mode: str) -> None:
    assert _uris(text) == tables


def test_sql_database_resources(sql_mode: str) -> None:
    assert _uris("DROP DATABASE prod", kind="database") == ["prod"]


def test_sql_labels_never_quote_identifiers_or_values(sql_mode: str) -> None:
    result = classify_sql("DELETE FROM secret_table; DROP TABLE other_secret")
    assert result.labels
    assert all("secret" not in label for label in result.labels)


def test_sql_labels_name_what_was_found(sql_mode: str) -> None:
    assert "sql:delete-without-where" in classify_sql("DELETE FROM t").labels
    assert "sql:drop" in classify_sql("DROP TABLE t").labels


def test_very_long_sql_is_still_classified(sql_mode: str) -> None:
    text = "SELECT 1;" * 20_000 + "DROP TABLE users"
    assert classify_sql(text).effect == "destructive"


def test_unterminated_string_hides_nothing_before_it(sql_mode: str) -> None:
    assert classify_sql("DROP TABLE users; SELECT 'oops").effect == "destructive"


# ---------------------------------------------------------------- shell details


def _shell(command: str | list[str], kind: str) -> list[str]:
    return [r.uri for r in classify_shell(command).resources if r.kind == kind]


def test_shell_path_resources() -> None:
    assert _shell("rm -rf /var/backups/db", "path") == ["/var/backups/db"]
    assert _shell("rm -rf build", "path") == ["build"]
    assert _shell("cat /etc/../etc/passwd", "path") == ["/etc/passwd"]
    assert _shell("echo hi > /srv/out.txt", "path") == ["/srv/out.txt"]
    assert _shell("echo hi 2>/dev/null", "path") == []


def test_shell_url_resources_drop_credentials_and_queries() -> None:
    uris = _shell("curl https://bob:hunter2@api.example.com/x?token=abc", "url")
    assert uris == ["https://api.example.com/x"]


def test_shell_kubernetes_resources() -> None:
    result = classify_shell("kubectl -n prod delete deploy/api")
    refs = [r for r in result.resources if r.kind == "kubernetes"]
    assert [(r.uri, r.attrs) for r in refs] == [
        ("deploy/api", {"namespace": "prod"}),
        ("scope/prod", {"namespace": "prod"}),
    ]
    refs = list(classify_shell("kubectl delete ns prod").resources)
    assert [(r.kind, r.uri) for r in refs] == [("kubernetes", "ns/prod")]


def test_shell_git_push_resources() -> None:
    refs = classify_shell("git push --force origin HEAD:main").resources
    assert [(r.kind, r.uri, r.attrs) for r in refs] == [
        ("git_remote", "origin", {"branch": "main"})
    ]


def test_argv_lists_are_not_reparsed() -> None:
    assert classify_shell(["rm", "-rf", "/"]).effect == "destructive"
    assert classify_shell(["echo", "rm -rf /"]).effect == "read"
    assert classify_shell(["bash", "-c", "rm -rf /"]).effect == "destructive"


def test_nesting_too_deep_fails_safe() -> None:
    command = "ls"
    for _ in range(10):
        command = f"bash -c {shlex.quote(command)}"
    result = classify_shell(command)
    assert result.effect == "destructive"
    assert "shell:too-deep" in result.labels


def test_unparseable_shell_fails_safe() -> None:
    result = classify_shell("echo 'unterminated")
    assert (result.effect, result.labels) == ("destructive", ("shell:unparsed",))


def test_shell_labels_never_quote_arguments() -> None:
    result = classify_shell("rm -rf /home/secret-project && curl -d x https://secret.example")
    assert result.labels
    assert all("secret" not in label for label in result.labels)


def test_shell_sql_resources_come_through() -> None:
    assert _shell("psql -c 'DROP TABLE users'", "table") == ["users"]


@pytest.mark.parametrize(
    "command",
    ["$(" * 3000 + ")" * 3000, "`a`" * 20_000, "<(" * 2000 + "ls" + ")" * 2000],
    ids=["nested-subst", "many-backticks", "process-subst"],
)
def test_pathological_commands_finish_quickly(command: str) -> None:
    started = time.perf_counter()
    classify_shell(command)
    assert time.perf_counter() - started < 10.0  # quadratic would take minutes


def test_huge_commands_fail_safe() -> None:
    result = classify_shell("echo " + "a" * 200_000)
    assert (result.effect, result.labels) == ("destructive", ("shell:too-large",))


def test_kubectl_namespace_scopes_every_subcommand() -> None:
    refs = classify_shell("kubectl -n prod scale deploy/web --replicas=0").resources
    assert [(r.kind, r.uri, r.attrs) for r in refs] == [
        ("kubernetes", "scope/prod", {"namespace": "prod"})
    ]


@pytest.mark.parametrize(
    ("endpoint", "path"),
    [
        ("repos/octo/app/", "repos/octo/app"),
        ("/repos//octo///app", "repos/octo/app"),
        ("repos/octo/./app", "repos/octo/app"),
        ("repos/octo/app/hooks/../", "repos/octo/app"),
        ("repos/octo%2Fapp", "repos/octo/app"),
        ("repos/octo/app/../../../../x", "x"),
        ("/", ""),
    ],
)
def test_gh_api_paths_are_normalized(endpoint: str, path: str) -> None:
    found = classify_shell(f"gh api -X DELETE {endpoint}")
    refs = [r.uri for r in found.resources if r.kind == "github_api"]
    assert refs == ([path] if path else [])
    assert found.effect == "destructive"


def test_gh_api_urls_become_paths() -> None:
    found = classify_shell("gh api -X DELETE https://ghe.example.com/api/v3/repos/octo/app?x=1")
    refs = [r for r in found.resources if r.kind == "github_api"]
    assert [(r.kind, r.uri, r.attrs) for r in refs] == [
        ("github_api", "repos/octo/app", {"method": "DELETE"})
    ]
