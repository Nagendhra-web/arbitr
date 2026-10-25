"""Shell commands: what they touch and how destructive they are.

A command line is split into simple commands on ``;``, ``&&``, ``||``, ``|``,
``&``, newlines and parentheses, with quoting handled by :mod:`shlex`. Command
substitutions (``$(...)``, backticks, ``<(...)``) and nested shells
(``bash -c``, ``eval``, ``ssh host cmd``, ``kubectl exec -- cmd``,
``xargs``, ``find -exec``) are classified too. Wrappers such as ``sudo``,
``env``, ``nohup`` and ``timeout`` are looked through.

The classifier errs on the side of caution. Comments are not stripped (a
``#`` could hide a command after it), and a command that cannot be parsed, or
nests too deeply, is treated as destructive.

Example:
    >>> classify_shell("ls && rm -rf build").effect
    'destructive'
    >>> classify_shell("git status").effect
    'read'
    >>> classify_shell("echo 'rm -rf /'").effect
    'read'
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from arbitr.resources.base import Extraction, make_ref
from arbitr.resources.extractors.paths import looks_like_path, path_ref
from arbitr.resources.extractors.sql import classify_sql
from arbitr.resources.extractors.urls import url_refs

if TYPE_CHECKING:
    from arbitr.core.spec import Effect

_MAX_DEPTH: Final = 8
_MAX_COMMAND: Final = 100_000
_SUBSTITUTION: Final = re.compile(r"[$<>]\(")
_PUNCT: Final = "();<>|&\n"
_ASSIGNMENT: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_REMOTE: Final = re.compile(r"^(?:[^/:@]+@)?[^/:]+:(?!//)")
_MONGO_DESTROY: Final = re.compile(
    r"\.(?:drop|dropDatabase|dropIndex|dropIndexes|deleteMany|remove)\s*\("
)
_MONGO_WRITE: Final = re.compile(
    r"\.(?:insert\w*|update\w*|replace\w*|deleteOne|findOneAndDelete|findOneAndUpdate"
    r"|create\w*|rename\w*|bulkWrite)\s*\("
)

_DESTRUCTIVE_PROGRAMS: Final = frozenset(
    {
        "rm",
        "shred",
        "unlink",
        "truncate",
        "srm",
        "wipe",
        "wipefs",
        "mkfs",
        "mke2fs",
        "mkswap",
        "fdisk",
        "sfdisk",
        "gdisk",
        "cfdisk",
        "parted",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "dropdb",
        "dropuser",
        "userdel",
        "groupdel",
        "deluser",
        "delgroup",
        "kexec",
    }
)
_WRITE_PROGRAMS: Final = frozenset(
    {
        "touch",
        "mkdir",
        "rmdir",
        "cp",
        "mv",
        "ln",
        "chmod",
        "chown",
        "chgrp",
        "tee",
        "install",
        "tar",
        "zip",
        "unzip",
        "gzip",
        "gunzip",
        "bzip2",
        "xz",
        "7z",
        "patch",
        "make",
        "cmake",
        "ninja",
        "pip",
        "pip3",
        "pipx",
        "uv",
        "poetry",
        "cargo",
        "go",
        "apt",
        "apt-get",
        "yum",
        "dnf",
        "apk",
        "brew",
        "pacman",
        "snap",
        "flatpak",
        "service",
        "kill",
        "pkill",
        "killall",
        "useradd",
        "usermod",
        "groupadd",
        "passwd",
        "chpasswd",
        "mount",
        "umount",
        "iptables",
        "ufw",
        "setfacl",
        "chattr",
        "createdb",
        "createuser",
        "pg_restore",
    }
)
_READ_PROGRAMS: Final = frozenset(
    {
        "ls",
        "dir",
        "cat",
        "head",
        "tail",
        "less",
        "more",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "ag",
        "ack",
        "echo",
        "printf",
        "pwd",
        "whoami",
        "id",
        "groups",
        "which",
        "whereis",
        "type",
        "wc",
        "sort",
        "uniq",
        "diff",
        "cmp",
        "comm",
        "stat",
        "file",
        "du",
        "df",
        "ps",
        "pstree",
        "top",
        "htop",
        "uname",
        "date",
        "cal",
        "hostname",
        "tree",
        "jq",
        "yq",
        "cut",
        "tr",
        "tac",
        "nl",
        "fold",
        "column",
        "basename",
        "dirname",
        "realpath",
        "readlink",
        "md5sum",
        "sha1sum",
        "sha256sum",
        "sha512sum",
        "base64",
        "true",
        "false",
        "test",
        "[",
        "sleep",
        "history",
        "man",
        "help",
        "uptime",
        "free",
        "lsof",
        "netstat",
        "ss",
        "ip",
        "ifconfig",
        "dig",
        "nslookup",
        "host",
        "ping",
        "traceroute",
        "locate",
        "xxd",
        "hexdump",
        "od",
        "strings",
        "zcat",
        "zless",
        "zgrep",
        "cd",
        "export",
        "set",
        "unset",
        "alias",
        "printenv",
        "seq",
        "yes",
        "expr",
        "bc",
        "pg_dump",
        "mysqldump",
        "lsblk",
        "blkid",
        "journalctl",
        "dmesg",
        "nproc",
        "getent",
        "last",
        "w",
        "who",
    }
)
_EXTERNAL_PROGRAMS: Final = frozenset(
    {
        "nc",
        "ncat",
        "netcat",
        "telnet",
        "socat",
        "sftp",
        "ftp",
        "lftp",
        "mail",
        "mailx",
        "sendmail",
        "mutt",
        "msmtp",
        "swaks",
        "ssmtp",
    }
)
_FILE_PROGRAMS: Final = frozenset(
    {"rm", "rmdir", "shred", "unlink", "truncate", "touch", "mkdir", "cp", "mv", "ln", "tee"}
)
_OWNER_FIRST: Final = frozenset({"chmod", "chown", "chgrp"})

_DESTROY_WORDS: Final = frozenset(
    {
        "delete",
        "destroy",
        "remove",
        "rm",
        "rb",
        "purge",
        "terminate",
        "uninstall",
        "wipe",
        "erase",
        "reset",
    }
)
_READ_WORDS: Final = frozenset(
    {
        "list",
        "ls",
        "describe",
        "show",
        "get",
        "info",
        "status",
        "view",
        "cat",
        "logs",
        "whoami",
        "version",
        "help",
        "history",
        "search",
        "template",
        "lint",
        "diff",
        "checks",
    }
)

Handler = Callable[[list[str], int], Extraction]


# ---------------------------------------------------------------- helpers


def _found(effect: Effect, label: str) -> Extraction:
    return Extraction(effect=effect, labels=(label,))


_SYSTEM_DIRS: Final = ("/bin/", "/usr/bin/", "/usr/local/bin/", "/sbin/", "/usr/sbin/")


def _is_trusted_location(arg0: str) -> bool:
    """A bare name (found on PATH) or a standard system folder.

    ``/srv/x/ls`` could be anything, so it is not judged by its name.
    """
    has_dir = "/" in arg0 or "\\" in arg0
    return not has_dir or any(
        arg0.startswith(d) and "/" not in arg0[len(d) :] for d in _SYSTEM_DIRS
    )


def _program(arg0: str) -> str:
    name = re.split(r"[/\\]", arg0)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat"):
        name = name.removesuffix(suffix)
    return "mkfs" if name.startswith("mkfs.") else name


def _short_flags(args: list[str]) -> str:
    """Every letter given in short option clusters such as ``-fdx``."""
    return "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))


def _positionals(args: list[str], with_value: frozenset[str] = frozenset()) -> list[str]:
    """Arguments that are not options or the values of options in ``with_value``."""
    out: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg.startswith("-") and arg != "-":
            skip = arg in with_value
        else:
            out.append(arg)
    return out


def _is_short(name: str) -> bool:
    return len(name) == 2 and name.startswith("-") and name != "--"  # noqa: PLR2004 - such as -c


def _option_values(args: list[str], names: frozenset[str]) -> list[str]:
    """Values of options in ``names``: ``-c X``, ``--command=X`` and ``-cX``."""
    values: list[str] = []
    for i, arg in enumerate(args):
        if arg in names:
            if i + 1 < len(args):
                values.append(args[i + 1])
            continue
        for name in names:
            if name.startswith("--") and arg.startswith(name + "="):
                values.append(arg[len(name) + 1 :])
            elif _is_short(name) and arg.startswith(name) and arg != name:
                values.append(arg[2:])
    return values


def _skip_options(args: list[str], with_value: frozenset[str]) -> list[str]:
    """Drop leading options (and their values) up to the first operand or ``--``."""
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "-":
        if args[i] == "--":
            return args[i + 1 :]
        i += 2 if args[i] in with_value else 1
    return args[i:]


def _sql_in(values: list[str], label: str) -> Extraction:
    result = Extraction(labels=(label,))
    for value in values:
        result = result.merge(classify_sql(value))
    return result


# ---------------------------------------------------------------- wrappers


def _unwrap_env(args: list[str]) -> list[str]:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-S", "--split-string") and i + 1 < len(args):
            return ["sh", "-c", args[i + 1], *args[i + 2 :]]
        if arg.startswith("--split-string="):
            return ["sh", "-c", arg.split("=", 1)[1], *args[i + 1 :]]
        if arg in ("-u", "--unset", "-C", "--chdir"):
            i += 2
        elif arg.startswith("-"):
            i += 1
        else:
            break
    return args[i:] or ["env"]


def _drop_first(with_value: frozenset[str]) -> Callable[[list[str]], list[str]]:
    def unwrap(args: list[str]) -> list[str]:
        return _skip_options(args, with_value)[1:]

    return unwrap


def _options_only(with_value: frozenset[str]) -> Callable[[list[str]], list[str]]:
    def unwrap(args: list[str]) -> list[str]:
        return _skip_options(args, with_value)

    return unwrap


def _unwrap_xargs(args: list[str]) -> list[str]:
    with_value = frozenset(
        {
            "-I",
            "-n",
            "-P",
            "-L",
            "-s",
            "-d",
            "-E",
            "-a",
            "--max-args",
            "--max-procs",
            "--replace",
            "--delimiter",
            "--arg-file",
            "--max-lines",
            "--eof",
        }
    )
    return _skip_options(args, with_value) or ["echo"]


def _unwrap_watch(args: list[str]) -> list[str]:
    rest = _skip_options(args, frozenset({"-n", "--interval", "-d", "--differences"}))
    return ["sh", "-c", " ".join(rest)] if rest else []


_WRAPPERS: Final[dict[str, Callable[[list[str]], list[str]]]] = {
    "sudo": _options_only(
        frozenset(
            {
                "-u",
                "-g",
                "-C",
                "-D",
                "-p",
                "-r",
                "-t",
                "-U",
                "-T",
                "--user",
                "--group",
                "--chdir",
                "--prompt",
                "--role",
                "--type",
                "--other-user",
                "--close-from",
            }
        )
    ),
    "doas": _options_only(frozenset({"-u", "-C"})),
    "env": _unwrap_env,
    "nohup": _options_only(frozenset()),
    "time": _options_only(frozenset({"-f", "-o", "--format", "--output"})),
    "nice": _options_only(frozenset({"-n", "--adjustment"})),
    "ionice": _options_only(frozenset({"-c", "-n", "-p"})),
    "stdbuf": _options_only(frozenset({"-i", "-o", "-e"})),
    "command": _options_only(frozenset()),
    "builtin": _options_only(frozenset()),
    "exec": _options_only(frozenset({"-a"})),
    "timeout": _drop_first(frozenset({"-s", "-k", "--signal", "--kill-after"})),
    "chroot": _drop_first(frozenset({"--userspec", "--groups"})),
    "flock": _drop_first(frozenset({"-w", "--timeout", "-E", "--conflict-exit-code"})),
    "xargs": _unwrap_xargs,
    "watch": _unwrap_watch,
}


# ---------------------------------------------------------------- nested commands


def _shell_c(args: list[str], depth: int) -> Extraction:
    """``sh -c CMD`` is classified. A script file is as opaque as ``python x.py``.

    A shell that reads its commands from stdin (``curl ... | sh``, ``bash -s``,
    a here-string) runs code nobody can see, so it counts as destructive.
    """
    for i, arg in enumerate(args):
        if arg == "--":
            break
        if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
            rest = args[i + 1 :]
            if not rest:
                return _found("destructive", "shell:stdin-script")
            return _command(rest[0], depth + 1)
    if {"--version", "--help"} & set(args):
        return _found("read", "shell:shell")
    if _script_operands(args) and "-s" not in args:
        return Extraction()
    return _found("destructive", "shell:stdin-script")


_SHELL_VALUE_OPTIONS: Final = frozenset({"-o", "-O", "+o", "+O", "--rcfile", "--init-file"})


def _script_operands(args: list[str]) -> list[str]:
    """Shell arguments that are not options or option values: a script and its args."""
    operands: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg in _SHELL_VALUE_OPTIONS:
            skip = True
        elif not arg.startswith(("-", "+")):
            operands.append(arg)
    return operands


def _eval(args: list[str], depth: int) -> Extraction:
    return _command(" ".join(args), depth + 1)


def _ssh(args: list[str], depth: int) -> Extraction:
    with_value = frozenset(
        {
            "-p",
            "-i",
            "-l",
            "-o",
            "-F",
            "-J",
            "-L",
            "-R",
            "-D",
            "-b",
            "-c",
            "-e",
            "-m",
            "-O",
            "-Q",
            "-S",
            "-W",
            "-w",
            "-E",
            "-B",
            "-I",
        }
    )
    rest = _skip_options(args, with_value)
    inner = _command(" ".join(rest[1:]), depth + 1) if len(rest) > 1 else Extraction()
    return inner.merge(_ssh_options(args, depth)).raised("external_comm", "shell:ssh")


_SSH_COMMAND_OPTIONS: Final = frozenset(
    {"proxycommand", "localcommand", "knownhostscommand", "remotecommand"}
)


def _ssh_options(args: list[str], depth: int) -> Extraction:
    """``-o ProxyCommand=...`` and similar options run a command."""
    result = Extraction()
    for option in _option_values(args, frozenset({"-o"})):
        parts = re.split(r"[=\s]", option.strip(), maxsplit=1)
        key, value = parts[0], parts[1] if len(parts) > 1 else ""
        if key.lower() in _SSH_COMMAND_OPTIONS and value.strip():
            result = result.merge(_command(value.strip(), depth + 1))
    return result


def _find(args: list[str], depth: int) -> Extraction:
    result = _found("read", "shell:find")
    if "-delete" in args:
        result = result.raised("destructive", "shell:find-delete")
    for i, arg in enumerate(args):
        if arg in ("-exec", "-execdir", "-ok", "-okdir"):
            inner: list[str] = []
            for token in args[i + 1 :]:
                if token in (";", "+"):
                    break
                inner.append(token)
            result = result.merge(_simple(inner, depth + 1))
    return result


# ---------------------------------------------------------------- git


_GIT_GLOBAL_VALUES: Final = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
)
_GIT_READ: Final = frozenset(
    {
        "status",
        "log",
        "diff",
        "show",
        "blame",
        "shortlog",
        "describe",
        "rev-parse",
        "rev-list",
        "ls-files",
        "ls-tree",
        "ls-remote",
        "cat-file",
        "grep",
        "whatchanged",
        "count-objects",
        "fsck",
        "show-ref",
        "for-each-ref",
        "name-rev",
        "check-ignore",
        "merge-base",
        "var",
        "help",
        "version",
        "cherry",
        "range-diff",
        "annotate",
    }
)


def _git_push(rest: list[str]) -> Extraction:
    flags = [a for a in rest if a.startswith("-")]
    positional = _positionals(rest, frozenset({"-o", "--push-option", "--repo", "--receive-pack"}))
    refspecs = positional[1:]
    destructive = (
        any(
            f in ("--force", "--mirror", "--delete", "--prune") or f.startswith("--force")
            for f in flags
        )
        or bool(set(_short_flags(flags)) & {"f", "d"})
        or any(r.startswith(("+", ":")) for r in refspecs)
    )
    result = (
        _found("destructive", "shell:git-push-force")
        if destructive
        else _found("write", "shell:git-push")
    )
    if positional:
        # One resource per pushed branch; "(current)" when no refspec names one.
        branches = [
            r.lstrip("+").rsplit(":", 1)[-1].removeprefix("refs/heads/") for r in refspecs
        ] or ["(current)"]
        refs = tuple(make_ref("git_remote", positional[0], {"branch": b}) for b in branches if b)
        result = result.merge(Extraction(resources=refs))
    return result


def _git_clean(rest: list[str]) -> Extraction:
    short = _short_flags(rest)
    if "n" in short or "--dry-run" in rest:
        return _found("read", "shell:git-clean")
    if "f" in short or "--force" in rest:
        return _found("destructive", "shell:git-clean")
    return _found("write", "shell:git-clean")


def _git_branch(rest: list[str]) -> Extraction:
    force = "-f" in rest or "--force" in rest
    if "-D" in rest or (force and ("-d" in rest or "--delete" in rest)):
        return _found("destructive", "shell:git-branch-delete")
    changes = {
        "-d",
        "--delete",
        "-m",
        "-M",
        "-c",
        "-C",
        "-u",
        "--set-upstream-to",
        "--unset-upstream",
    }
    if any(a in changes for a in rest) or any(not a.startswith("-") for a in rest):
        return _found("write", "shell:git-branch")
    return _found("read", "shell:git-branch")


def _git_restore(rest: list[str]) -> Extraction:
    staged = "--staged" in rest or "-S" in rest
    worktree = "--worktree" in rest or "-W" in rest
    if staged and not worktree:
        return _found("write", "shell:git-restore")
    return _found("destructive", "shell:git-restore")


def _git_first_word(
    destructive: set[str], read: set[str], label: str
) -> Callable[[list[str]], Extraction]:
    def handle(rest: list[str]) -> Extraction:
        first = next((a for a in rest if not a.startswith("-")), "")
        if first in destructive:
            return _found("destructive", label)
        return _found("read" if first in read or (not first and "" in read) else "write", label)

    return handle


def _git_flag(
    flags: set[str], label: str, *, prefix: bool = False
) -> Callable[[list[str]], Extraction]:
    def handle(rest: list[str]) -> Extraction:
        hit = any(a in flags or (prefix and a.startswith(tuple(flags))) for a in rest)
        return _found("destructive" if hit else "write", label)

    return handle


def _git_checkout(rest: list[str]) -> Extraction:
    discard = "--" in rest or "-f" in rest or "--force" in rest or "." in rest
    return _found("destructive" if discard else "write", "shell:git-checkout")


_GIT_SUBCOMMANDS: Final[dict[str, Callable[[list[str]], Extraction]]] = {
    "push": _git_push,
    "clean": _git_clean,
    "branch": _git_branch,
    "restore": _git_restore,
    "checkout": _git_checkout,
    "reset": _git_flag({"--hard"}, "shell:git-reset"),
    "switch": _git_flag({"-f", "--force", "--discard-changes"}, "shell:git-switch"),
    "gc": _git_flag({"--prune"}, "shell:git-gc", prefix=True),
    "update-ref": _git_flag({"-d"}, "shell:git-update-ref"),
    "stash": _git_first_word({"drop", "clear"}, {"list", "show"}, "shell:git-stash"),
    "reflog": _git_first_word({"expire", "delete"}, {"", "show"}, "shell:git-reflog"),
    "remote": _git_first_word(set(), {"", "show", "get-url"}, "shell:git-remote"),
    "tag": _git_first_word(set(), {""}, "shell:git-tag"),
}


_GIT_EXEC_KEY: Final = re.compile(
    r"^(?:core\.(?:sshcommand|hookspath|pager|editor|fsmonitor|gitproxy|askpass)"
    r"|diff\.external|.*\.textconv|filter\..*|gpg\.(?:.*\.)?program|credential\..*"
    r"|sequence\.editor|include\.path|includeif\..*|uploadpack\.packobjectshook"
    r"|merge\..*\.driver|diff\..*\.command|difftool\..*|mergetool\..*|ssh\.variant"
    r"|pager\..*|remote\..*\.(?:uploadpack|receivepack|vcs)|protocol\..*"
    r"|core\.alternaterefscommand|url\..*\.insteadof)$"
)


def _git_config_runs_code(configs: list[str]) -> bool:
    for config in configs:
        key, _, value = config.partition("=")
        key = key.strip().lower()
        if key.startswith("alias.") and value.lstrip().startswith("!"):
            return True
        if _GIT_EXEC_KEY.match(key):
            return True
    return False


def _git(args: list[str], depth: int) -> Extraction:
    rest = args
    configs: list[str] = []
    while rest and rest[0].startswith("-"):
        if rest[0] == "-c" and len(rest) > 1:
            configs.append(rest[1])
        if rest[0].startswith("--config-env="):
            configs.append(rest[0].split("=", 1)[1])
        if rest[0].startswith("--exec-path="):
            configs.append("core.hooksPath=")  # an exec path runs its own helpers
        rest = rest[2:] if rest[0] in _GIT_GLOBAL_VALUES else rest[1:]
    if _git_config_runs_code(configs):
        return _found("destructive", "shell:git-config-exec")
    if not rest:
        return Extraction()
    sub, rest = rest[0], rest[1:]
    if sub in ("filter-branch", "filter-repo"):
        return _found("destructive", "shell:git-filter")
    if sub in _GIT_READ:
        return _found("read", "shell:git")
    handler = _GIT_SUBCOMMANDS.get(sub)
    return handler(rest) if handler else _found("write", "shell:git")


# ---------------------------------------------------------------- infrastructure


def _terraform(args: list[str], depth: int) -> Extraction:
    positional = _positionals(args)
    sub = positional[0] if positional else ""
    second = positional[1] if len(positional) > 1 else ""
    destroy = (
        sub == "destroy"
        or (sub == "apply" and ("-destroy" in args or "--destroy" in args))
        or (sub == "state" and second == "rm")
        or (sub == "workspace" and second == "delete")
    )
    if destroy:
        return _found("destructive", "shell:terraform-destroy")
    reads = {"plan", "validate", "show", "output", "version", "graph", "providers", "console"}
    if sub in reads or (sub == "state" and second in ("list", "show", "pull")):
        return _found("read", "shell:terraform")
    return _found("write", "shell:terraform")


_KUBECTL_VALUES: Final = frozenset(
    {
        "-n",
        "--namespace",
        "--context",
        "--kubeconfig",
        "-s",
        "--server",
        "--cluster",
        "--user",
        "--token",
        "-l",
        "--selector",
        "-f",
        "--filename",
        "-o",
        "--output",
        "-c",
        "--container",
        "--as",
        "--request-timeout",
        "-k",
        "--kustomize",
        "--field-selector",
        "--timeout",
        "--grace-period",
    }
)
_KUBECTL_READ: Final = frozenset(
    {
        "get",
        "describe",
        "logs",
        "top",
        "explain",
        "version",
        "api-resources",
        "api-versions",
        "cluster-info",
        "diff",
        "events",
        "auth",
        "wait",
    }
)


def _kubectl_objects(positional: list[str], namespace: str | None) -> Extraction:
    names = positional[1:]
    objects = [n for n in names if "/" in n]
    if not objects and names:
        kind, rest = names[0], names[1:]
        objects = [f"{kind}/{n}" for n in rest] or [f"{kind}/*"]
    attrs = {"namespace": namespace} if namespace else {}
    return Extraction(resources=tuple(make_ref("kubernetes", o, attrs) for o in objects))


def _kubectl(args: list[str], depth: int) -> Extraction:
    inner: list[str] = []
    if "--" in args:
        cut = args.index("--")
        args, inner = args[:cut], args[cut + 1 :]
    namespaces = _option_values(args, frozenset({"-n", "--namespace"}))
    scope = Extraction(
        resources=tuple(
            make_ref("kubernetes", f"scope/{ns}", {"namespace": ns}) for ns in namespaces
        )
    )
    positional = _positionals(args, _KUBECTL_VALUES)
    sub = positional[0] if positional else ""
    second = positional[1] if len(positional) > 1 else ""
    if sub == "delete":
        found = _found("destructive", "shell:kubectl-delete")
        objects = _kubectl_objects(positional, namespaces[-1] if namespaces else None)
        return found.merge(objects).merge(scope)
    if (sub == "replace" and "--force" in args) or (sub == "apply" and "--prune" in args):
        return _found("destructive", "shell:kubectl").merge(scope)
    if sub == "exec":
        return _simple(inner, depth + 1).raised("write", "shell:kubectl-exec").merge(scope)
    reads = sub in _KUBECTL_READ
    reads |= sub == "rollout" and second in ("status", "history")
    reads |= sub == "config" and second in ("view", "get-contexts", "current-context")
    return _found("read" if reads else "write", "shell:kubectl").merge(scope)


def _cloud_effect(positional: list[str]) -> Effect:
    if any(
        p in _DESTROY_WORDS
        or p.startswith(("delete-", "destroy-"))
        or p.endswith((":destroy", ":delete", ":remove", ":reset"))
        for p in positional
    ):
        return "destructive"
    if any(p in _READ_WORDS or p.startswith(("get-", "list-", "describe-")) for p in positional):
        return "read"
    return "write"


def _cloud(args: list[str], depth: int) -> Extraction:
    positional = _positionals(args)
    if positional[:1] == ["rsync"] and "-d" in args:
        return _found("destructive", "shell:cloud-cli")
    return _found(_cloud_effect(positional), "shell:cloud-cli")


_AWS_GLOBAL_VALUES: Final = frozenset(
    {
        "--region",
        "--profile",
        "--output",
        "--endpoint-url",
        "--query",
        "--color",
        "--ca-bundle",
        "--cli-read-timeout",
        "--cli-connect-timeout",
        "--cli-binary-format",
    }
)


def _aws(args: list[str], depth: int) -> Extraction:
    positional = _positionals(args, _AWS_GLOBAL_VALUES)
    service = positional[0] if positional else ""
    op = positional[1] if len(positional) > 1 else ""
    attrs = {}
    for key in ("region", "profile"):
        values = _option_values(args, frozenset({f"--{key}"}))
        if values:
            attrs[key] = values[-1]
    refs = (make_ref("aws", f"aws:{service}", attrs),) if service else ()
    if (
        op in ("rm", "rb")
        or "--delete" in args
        or op.startswith(("delete-", "terminate-", "deregister-", "purge-", "destroy-"))
    ):
        effect: Effect = "destructive"
    elif op.startswith(("describe-", "list-", "get-", "head-")) or op in ("ls", "wait", "help"):
        effect = "read"
    else:
        effect = "write"
    return Extraction(resources=refs, effect=effect, labels=("shell:aws",))


_DOCKER_GROUPS: Final = frozenset(
    {
        "container",
        "image",
        "volume",
        "network",
        "system",
        "builder",
        "buildx",
        "context",
        "plugin",
        "secret",
        "config",
        "node",
        "service",
        "stack",
    }
)
_DOCKER_READ: Final = frozenset(
    {
        "ps",
        "images",
        "logs",
        "inspect",
        "version",
        "info",
        "stats",
        "top",
        "history",
        "port",
        "diff",
        "search",
        "events",
    }
)
_DOCKER_EXEC_VALUES: Final = frozenset(
    {"-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir", "--detach-keys"}
)


def _docker_exec(rest: list[str], depth: int) -> Extraction:
    tail = _skip_options(rest, _DOCKER_EXEC_VALUES)
    return _simple(tail[1:], depth + 1).raised("write", "shell:docker-exec")


def _compose(args: list[str], depth: int) -> Extraction:
    values = frozenset(
        {"-f", "--file", "-p", "--project-name", "--profile", "--env-file", "--project-directory"}
    )
    rest = _skip_options(args, values)
    sub, rest = (rest[0], rest[1:]) if rest else ("", [])
    if sub == "rm" or (sub == "down" and ({"-v", "--volumes", "--rmi"} & set(rest))):
        return _found("destructive", "shell:docker")
    if sub == "exec":
        return _docker_exec(rest, depth)
    reads = {"ps", "logs", "config", "ls", "images", "top", "version", "port", "events"}
    return _found("read" if sub in reads else "write", "shell:docker")


def _docker(args: list[str], depth: int) -> Extraction:
    rest = _skip_options(args, frozenset({"-H", "--host", "--context", "-c", "--config", "-l"}))
    sub, rest = (rest[0], rest[1:]) if rest else ("", [])
    if sub == "compose":
        return _compose(rest, depth)
    if sub in ("rm", "rmi"):
        return _found("destructive", "shell:docker")
    if sub in _DOCKER_GROUPS:
        action = next((a for a in rest if not a.startswith("-")), "")
        if action in ("rm", "remove", "prune", "delete"):
            return _found("destructive", "shell:docker")
        reads = action in ("ls", "list", "inspect", "ps", "df", "info", "history")
        return _found("read" if reads else "write", "shell:docker")
    if sub == "exec":
        return _docker_exec(rest, depth)
    return _found("read" if sub in _DOCKER_READ else "write", "shell:docker")


# ---------------------------------------------------------------- other tools


_GH_API_VALUE: Final = frozenset("XHfFqtp")
_HTTP_METHODS: Final = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_GH_API_LONG_VALUE: Final = frozenset(
    {"--method", "--header", "--field", "--raw-field", "--jq", "--template", "--preview",
     "--input", "--hostname", "--cache"}
)  # fmt: skip


def _gh_cluster(cluster: str, following: str) -> tuple[str, str, bool]:
    """Read a short-flag group such as ``-iXDELETE``.

    Returns the value-taking flag, its value, and whether the value is the next argument.
    """
    for k, char in enumerate(cluster):
        if char in _GH_API_VALUE:
            rest = cluster[k + 1 :].removeprefix("=")  # pflag also accepts -X=DELETE
            return char, rest or following, not cluster[k + 1 :]
    return "", "", False


def _gh_api_call(args: list[str]) -> tuple[str, str]:
    """The HTTP method and path of ``gh api``, read like gh's flag parser.

    gh sends POST when fields or input are given and no method is set, and GET
    otherwise. Bundled short flags such as ``-iXDELETE`` are understood.
    """
    method: str | None = None
    has_body = False
    path = ""
    i = 0
    while i < len(args):
        arg = args[i]
        following = args[i + 1] if i + 1 < len(args) else ""
        if arg.startswith("--"):
            name, eq, value = arg.partition("=")
            if name in _GH_API_LONG_VALUE and not eq:
                value = following
                i += 1
            if name == "--method":
                method = value
            has_body = has_body or name in ("--field", "--raw-field", "--input")
        elif arg.startswith("-") and arg != "-":
            char, value, used_next = _gh_cluster(arg[1:], following)
            i += 1 if used_next else 0
            method = value if char == "X" else method
            has_body = has_body or char in ("f", "F")
        elif not path:
            path = arg
        i += 1
    if method is None:
        method = "POST" if has_body else "GET"
    return method.strip().strip("'\"").strip().upper(), _gh_api_path(path)


def _gh_api_path(endpoint: str) -> str:
    """``repos/o/r`` from ``/repos/o/r``, a full API URL, or GitHub Enterprise's ``/api/v3``."""
    if "://" in endpoint:
        endpoint = urlsplit(endpoint).path
    endpoint = endpoint.split("?", 1)[0].split("#", 1)[0].lstrip("/")
    return endpoint.removeprefix("api/v3/")


def _gh(args: list[str], depth: int) -> Extraction:
    positional = _positionals(args, frozenset({"-X", "--method", "-R", "--repo"}))
    if positional[:1] != ["api"]:
        return _found(_cloud_effect(positional), "shell:gh")
    method, path = _gh_api_call(args[args.index("api") + 1 :])
    refs = (make_ref("github_api", path, {"method": method}),) if path else ()
    if method == "DELETE" or method not in _HTTP_METHODS:
        effect: Effect = "destructive"  # an unknown method fails safe
    elif method in ("GET", "HEAD"):
        effect = "read"
    else:
        effect = "write"
    return Extraction(resources=refs, effect=effect, labels=("shell:gh-api",))


def _npm(args: list[str], depth: int) -> Extraction:
    positional = _positionals(args)
    sub = positional[0] if positional else ""
    if sub == "unpublish":
        return _found("destructive", "shell:npm-unpublish")
    reads = {"ls", "list", "view", "info", "outdated", "search", "whoami", "help", "explain", "why"}
    return _found("read" if sub in reads else "write", "shell:npm")


_REDIS_DESTROY: Final = frozenset({"FLUSHALL", "FLUSHDB", "DEL", "UNLINK", "SHUTDOWN", "SWAPDB"})
_REDIS_READ: Final = frozenset(
    {
        "GET",
        "MGET",
        "KEYS",
        "SCAN",
        "TTL",
        "PTTL",
        "EXISTS",
        "INFO",
        "PING",
        "TYPE",
        "DBSIZE",
        "HGET",
        "HGETALL",
        "HKEYS",
        "HVALS",
        "HLEN",
        "SMEMBERS",
        "SCARD",
        "LRANGE",
        "LLEN",
        "ZRANGE",
        "ZCARD",
        "STRLEN",
    }
)


def _redis(args: list[str], depth: int) -> Extraction:
    values = frozenset({"-h", "-p", "-a", "-n", "-u", "-s", "-r", "-i", "--user", "--pass"})
    positional = _positionals(args, values)
    if not positional:
        return Extraction()
    command = positional[0].upper()
    if command in _REDIS_DESTROY:
        return _found("destructive", "shell:redis")
    return _found("read" if command in _REDIS_READ else "write", "shell:redis")


def _sql_option(*names: str) -> Handler:
    def handle(args: list[str], depth: int) -> Extraction:
        values = _option_values(args, frozenset(names))
        return _sql_in(values, "shell:sql-client") if values else Extraction()

    return handle


def _sql_positional(args: list[str], depth: int) -> Extraction:
    values = frozenset({"-cmd", "-init", "-separator", "-newline", "-nullvalue", "-c"})
    statements = _positionals(args, values)[1:] + _option_values(args, frozenset({"-c", "-cmd"}))
    return _sql_in(statements, "shell:sql-client") if statements else Extraction()


def _cockroach(args: list[str], depth: int) -> Extraction:
    return _sql_option("-e", "--execute")(args, depth)


def _bq(args: list[str], depth: int) -> Extraction:
    positional = _positionals(args)
    if positional[:1] == ["query"]:
        return _sql_in(positional[1:], "shell:bq")
    return _found(_cloud_effect(positional[:1]), "shell:bq")


def _mongo(args: list[str], depth: int) -> Extraction:
    scripts = _option_values(args, frozenset({"--eval"}))
    if not scripts:
        return Extraction()
    if any(_MONGO_DESTROY.search(s) for s in scripts):
        return _found("destructive", "shell:mongo")
    if any(_MONGO_WRITE.search(s) for s in scripts):
        return _found("write", "shell:mongo")
    return _found("read", "shell:mongo")


def _crontab(args: list[str], depth: int) -> Extraction:
    if "-r" in args:
        return _found("destructive", "shell:crontab")
    return _found("read" if "-l" in args else "write", "shell:crontab")


def _http_method(args: list[str]) -> str | None:
    methods = _option_values(args, frozenset({"-X", "--request"}))
    return methods[-1].upper() if methods else None


def _curl(args: list[str], depth: int) -> Extraction:
    method = _http_method(args)
    if method == "DELETE":
        return _found("destructive", "shell:curl-delete")
    uploads = ("-d", "-F", "-T", "--json", "--form", "--upload-file", "--data")
    upload = any(a.startswith(uploads) for a in args)
    if upload or method in ("POST", "PUT", "PATCH"):
        return _found("external_comm", "shell:curl-upload")
    return _found("read", "shell:curl")


def _wget(args: list[str], depth: int) -> Extraction:
    methods = [m.upper() for m in _option_values(args, frozenset({"--method"}))]
    if "DELETE" in methods:
        return _found("destructive", "shell:wget")
    posts = ("--post-data", "--post-file", "--body-data", "--body-file")
    if any(a.startswith(posts) for a in args) or set(methods) & {"POST", "PUT", "PATCH"}:
        return _found("external_comm", "shell:wget")
    return _found("write", "shell:wget")


_HTTP_DATA: Final = re.compile(r"^[^=:@]+(?::=@?|=@?|@)(?!=)")


def _httpie(args: list[str], depth: int) -> Extraction:
    positional = _positionals(args, frozenset({"-a", "--auth", "-o", "--output", "--session"}))
    methods = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
    method = positional[0].upper() if positional and positional[0].upper() in methods else None
    items = positional[2:] if method else positional[1:]
    data = any(_HTTP_DATA.match(item) and "==" not in item for item in items)
    if method == "DELETE":
        return _found("destructive", "shell:http")
    if method in ("POST", "PUT", "PATCH") or (method is None and data):
        return _found("external_comm", "shell:http")
    return _found("read", "shell:http")


def _rsync(args: list[str], depth: int) -> Extraction:
    shells = _option_values(args, frozenset({"-e", "--rsh"}))
    if shells:
        inner = Extraction()
        for shell in shells:
            inner = inner.merge(_command(shell, depth + 1))
        return inner.merge(_rsync([a for a in args if a not in shells], depth))
    if any(a.startswith(("--delete", "--remove-source-files")) for a in args):
        return _found("destructive", "shell:rsync")
    if any(_REMOTE.match(p) or p.startswith("rsync://") for p in _positionals(args)):
        return _found("external_comm", "shell:rsync")
    return _found("write", "shell:rsync")


def _scp(args: list[str], depth: int) -> Extraction:
    remote = any(_REMOTE.match(p) for p in _positionals(args, frozenset({"-P", "-i", "-o"})))
    found = _found("external_comm" if remote else "write", "shell:scp")
    return found.merge(_ssh_options(args, depth))


def _dd(args: list[str], depth: int) -> Extraction:
    targets = [a[3:] for a in args if a.startswith("of=")]
    if not targets:
        return _found("read", "shell:dd")
    refs = tuple(r for r in (path_ref(t) for t in targets) if r is not None)
    return Extraction(resources=refs, effect="destructive", labels=("shell:dd",))


def _sed_skip(script: str, start: int, delim: str) -> int:
    """Index just past the next unescaped ``delim`` after ``start``."""
    i = start + 1
    while i < len(script):
        if script[i] == "\\":
            i += 2
            continue
        if script[i] == delim:
            return i + 1
        i += 1
    return len(script)


def _sed_line_end(script: str, i: int) -> int:
    end = script.find("\n", i)
    return len(script) if end < 0 else end


def _sed_effect(script: str) -> Effect | None:  # noqa: C901 - a small sed parser
    """``destructive`` for the ``e`` command or flag, ``write`` for ``w``, else None."""
    effect: Effect | None = None
    i, n = 0, len(script)
    while i < n:
        c = script[i]
        if c in " \t\n;{}!" or c.isdigit() or c in "$,~+":
            i += 1
        elif c == "/":
            i = _sed_skip(script, i, "/")
        elif c == "\\" and i + 1 < n:
            i = _sed_skip(script, i + 1, script[i + 1])
        elif c in "sy" and i + 1 < n:
            delim = script[i + 1]
            i = _sed_skip(script, _sed_skip(script, i + 1, delim) - 1, delim)
            flags = re.match(r"[0-9a-zA-Z]*", script[i:])
            letters = flags.group(0) if flags else ""
            if c == "s" and "e" in letters:
                return "destructive"
            if c == "s" and "w" in letters:
                effect = "write"
                i = _sed_line_end(script, i)
            else:
                i += len(letters)
        elif c == "e":
            return "destructive"
        elif c in "wW":
            effect = "write"
            i = _sed_line_end(script, i)
        elif c in "aicrRbtT:":
            i = _sed_line_end(script, i)
        else:
            i += 1
    return effect


def _sed_cluster(cluster: str, following: str | None) -> tuple[str | None, bool, bool]:
    """Read one short-option cluster such as ``-ne`` or ``-nes/a/b/``.

    Returns (script, uses the next argument, reads a script file).
    """
    for k, char in enumerate(cluster):
        if char in "il":
            return None, False, False  # -i takes a suffix, -l a length
        if char == "f":
            return None, False, True
        if char == "e":
            rest = cluster[k + 1 :]
            if rest:
                return rest, False, False
            return following, following is not None, False
    return None, False, False


def _sed_scripts(args: list[str]) -> tuple[list[str], bool]:
    """Every ``-e`` script, also inside clusters, and whether a script file is used."""
    scripts: list[str] = []
    from_file = False
    i = 0
    while i < len(args):
        arg = args[i]
        following = args[i + 1] if i + 1 < len(args) else None
        expression = _long_option(arg, "--expression", shortest=3) if arg.startswith("--") else None
        if (arg == "-e" or expression == "") and following is not None:
            scripts.append(following)
            i += 1
        elif expression:
            scripts.append(expression)
        elif arg == "-f" or (arg.startswith("--") and _long_option(arg, "--file") is not None):
            from_file = True
        elif arg.startswith("-") and not arg.startswith("--") and len(arg) > 2:  # noqa: PLR2004 - a cluster
            script, used_next, reads_file = _sed_cluster(arg[1:], following)
            from_file = from_file or reads_file
            if script is not None:
                scripts.append(script)
            i += 1 if used_next else 0
        i += 1
    return scripts, from_file


def _sed(args: list[str], depth: int) -> Extraction:
    in_place = "--in-place" in args or any(
        a.startswith("--in-place=") or (a.startswith("-") and not a.startswith("--") and "i" in a)
        for a in args
    )
    scripts, from_file = _sed_scripts(args)
    if from_file:
        return _found("write", "shell:sed") if in_place else Extraction()
    if not scripts:
        values = frozenset({"-e", "--expression", "-l", "--line-length"})
        scripts = _positionals(args, values)[:1]
    effect: Effect = "write" if in_place else "read"
    for script in scripts:
        found = _sed_effect(script)
        if found == "destructive":
            return _found("destructive", "shell:sed-exec")
        if found == "write":
            effect = "write"
    return _found(effect, "shell:sed")


def _perl(args: list[str], depth: int) -> Extraction:
    return _found("write", "shell:perl") if "i" in _short_flags(args) else Extraction()


_AWK_EXEC: Final = re.compile(
    r"\bsystem\s*\(|(?<!\|)\|(?!\|)|@\s*[A-Za-z_]\w*\s*\(|@load\b|@include\b"
)
_AWK_WRITE: Final = re.compile(r"\bprintf?\b[^;}]*>")


def _long_option(arg: str, full: str, shortest: int = 4) -> str | None:
    """The value of ``full`` given as itself or a getopt-style prefix.

    ``shortest`` is the shortest prefix the tool accepts as unambiguous, from
    its own option table (``--e`` for sed's ``--expression``).
    """
    name, eq, value = arg.partition("=")
    if len(name) >= shortest and full.startswith(name):
        return value if eq else ""
    return None


def _attached(arg: str, short: str) -> str | None:
    """The value of a short option written together with it: ``-lLIB``."""
    if arg.startswith(short) and not arg.startswith("--") and len(arg) > len(short):
        return arg[len(short) :]
    return None


# gawk's long options and whether each takes a value. A prefix that names one
# option unambiguously counts as that option, the way getopt reads it.
_GAWK_LONG: Final = {
    "assign": True, "bignum": False, "characters-as-bytes": False, "copyright": False,
    "csv": False, "debug": False, "dump-variables": False, "exec": True,
    "field-separator": True, "file": True, "gen-pot": False, "help": False, "include": True,
    "lint": False, "load": True, "no-optimize": False, "non-decimal-data": False,
    "optimize": False, "posix": False, "pretty-print": False, "profile": False,
    "re-interval": False, "sandbox": False, "source": True, "traditional": False,
    "use-lc-numeric": False, "version": False,
}  # fmt: skip
_GAWK_SHORT_VALUE: Final = frozenset("fFveEil")
_GAWK_SHORT_OPTIONAL: Final = frozenset("dDLop")
_GAWK_SHORT_FLAGS: Final = frozenset("bcCghIMnNOPrsStVy")
_GAWK_SHORT_TO_LONG: Final = {
    "f": "file", "F": "field-separator", "v": "assign", "e": "source", "E": "exec",
    "i": "include", "l": "load",
}  # fmt: skip


def _gawk_long(name: str) -> str | None:
    """The full gawk option a long-option prefix names, or None when unknown or ambiguous."""
    if name in _GAWK_LONG:
        return name
    matches = [full for full in _GAWK_LONG if full.startswith(name)]
    return matches[0] if len(matches) == 1 else None


@dataclass
class _AwkCall:
    """What an awk command line asks for, read like gawk's own option parser."""

    sources: list[str] = field(default_factory=list)
    program_file: bool = False
    loads_code: bool = False
    in_place: bool = False
    unknown_option: bool = False
    operands: list[str] = field(default_factory=list)

    def take(self, option: str, value: str) -> None:
        if option in ("file", "exec"):
            self.program_file = True
        elif option == "source":
            self.sources.append(value)
        elif option == "include":
            if value == "inplace":
                self.in_place = True
            else:
                self.loads_code = True
        elif option == "load":
            self.loads_code = True


def _awk_cluster(call: _AwkCall, cluster: str, following: str | None) -> bool:
    """Read ``-F|`` or ``-vx=1`` or ``-f prog``. Returns whether ``following`` was used.

    An unknown short option fails closed, like an unknown long one. (``-W``
    is rewritten to a long option before this runs.)
    """
    for k, char in enumerate(cluster):
        if char not in _GAWK_SHORT_VALUE | _GAWK_SHORT_OPTIONAL | _GAWK_SHORT_FLAGS:
            call.unknown_option = True
            return False
        if char in _GAWK_SHORT_VALUE:
            rest = cluster[k + 1 :]
            value = rest if rest else (following or "")
            call.take(_GAWK_SHORT_TO_LONG[char], value)
            return not rest and following is not None
        if char in _GAWK_SHORT_OPTIONAL:
            return False
    return False


def _without_w(args: list[str]) -> list[str]:
    """Rewrite gawk's ``-W name[=value]`` and ``-Wname[=value]`` as ``--name[=value]``."""
    out: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-W" and i + 1 < len(args):
            out.append("--" + args[i + 1])
            i += 2
            continue
        out.append("--" + arg[2:] if arg.startswith("-W") and len(arg) > 2 else arg)  # noqa: PLR2004 - "-W"
        i += 1
    return out


def _parse_awk(args: list[str]) -> _AwkCall:
    call = _AwkCall()
    args = _without_w(args)
    i = 0
    while i < len(args):
        arg = args[i]
        following = args[i + 1] if i + 1 < len(args) else None
        if arg == "--":
            i += 1
            break
        if arg.startswith("--"):
            name, eq, value = arg[2:].partition("=")
            option = _gawk_long(name)
            if option is None:
                call.unknown_option = True
            else:
                if _GAWK_LONG[option] and not eq:
                    value = following or ""
                    i += 1
                call.take(option, value)
        elif arg.startswith("-") and arg != "-":
            i += 1 if _awk_cluster(call, arg[1:], following) else 0
        else:
            break
        i += 1
    call.operands = args[i:]
    return call


def _awk(args: list[str], depth: int) -> Extraction:
    call = _parse_awk(args)
    if call.unknown_option:
        return _found("destructive", "shell:awk-unknown-option")
    if call.loads_code:
        return _found("destructive", "shell:awk-exec")
    programs = list(call.sources)
    if not programs and not call.program_file and call.operands:
        programs = call.operands[:1]
    program = "\n".join(programs)
    if _AWK_EXEC.search(program):
        return _found("destructive", "shell:awk-exec")
    if call.program_file and not call.sources:
        return _found("write", "shell:awk") if call.in_place else Extraction()
    writes = call.in_place or bool(_AWK_WRITE.search(program))
    return _found("write" if writes else "read", "shell:awk")


_TAR_EXEC: Final = (
    "--to-command",
    "--checkpoint-action",
    "--use-compress-program",
    "--info-script",
    "--new-volume-script",
    "--rsh-command",
)


_TAR_BENIGN: Final = frozenset({"--checkpoint"})


def _tar_runs_code(args: list[str]) -> bool:
    """Exec options, also abbreviated (``--to-com``), in clusters or old style (``xIf``)."""
    for index, arg in enumerate(args):
        if arg.startswith("--"):
            name = arg.split("=", 1)[0]
            known = len(name) > 3 and name not in _TAR_BENIGN  # noqa: PLR2004 - at least --xx
            if known and any(option.startswith(name) for option in _TAR_EXEC):
                return True
        elif (arg.startswith("-") or index == 0) and {"I", "F"} & set(arg.lstrip("-")):
            return True
    return False


def _tar(args: list[str], depth: int) -> Extraction:
    if _tar_runs_code(args):
        return _found("destructive", "shell:tar-exec")
    return _found("write", "shell:tar")


def _systemctl(args: list[str], depth: int) -> Extraction:
    positional = _positionals(args)
    reads = {
        "status",
        "list-units",
        "list-unit-files",
        "is-active",
        "is-enabled",
        "show",
        "cat",
        "list-timers",
        "list-dependencies",
        "is-failed",
    }
    return _found(
        "read" if positional[:1] and positional[0] in reads else "write", "shell:systemctl"
    )


def _handlers() -> dict[str, Handler]:
    table: dict[str, Handler] = {
        "eval": _eval,
        "ssh": _ssh,
        "find": _find,
        "git": _git,
        "terraform": _terraform,
        "tofu": _terraform,
        "terragrunt": _terraform,
        "kubectl": _kubectl,
        "oc": _kubectl,
        "aws": _aws,
        "docker": _docker,
        "podman": _docker,
        "nerdctl": _docker,
        "docker-compose": _compose,
        "podman-compose": _compose,
        "gh": _gh,
        "npm": _npm,
        "pnpm": _npm,
        "yarn": _npm,
        "redis-cli": _redis,
        "psql": _sql_option("-c", "--command"),
        "mysql": _sql_option("-e", "--execute"),
        "mariadb": _sql_option("-e", "--execute"),
        "clickhouse-client": _sql_option("-q", "--query"),
        "snowsql": _sql_option("-q", "--query"),
        "sqlite3": _sql_positional,
        "duckdb": _sql_positional,
        "cockroach": _cockroach,
        "bq": _bq,
        "mongo": _mongo,
        "mongosh": _mongo,
        "crontab": _crontab,
        "curl": _curl,
        "wget": _wget,
        "http": _httpie,
        "https": _httpie,
        "xh": _httpie,
        "xhs": _httpie,
        "rsync": _rsync,
        "scp": _scp,
        "dd": _dd,
        "sed": _sed,
        "perl": _perl,
        "awk": _awk,
        "gawk": _awk,
        "mawk": _awk,
        "nawk": _awk,
        "tar": _tar,
        "systemctl": _systemctl,
    }
    for shell in ("sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "mksh"):
        table[shell] = _shell_c
    for cloud in (
        "helm",
        "gcloud",
        "gsutil",
        "az",
        "doctl",
        "heroku",
        "fly",
        "flyctl",
        "vercel",
        "netlify",
        "firebase",
        "supabase",
        "pulumi",
        "hcloud",
        "linode-cli",
        "oci",
        "ibmcloud",
        "scw",
        "wrangler",
        "railway",
    ):
        table[cloud] = _cloud
    return table


_HANDLERS: Final = _handlers()


# ---------------------------------------------------------------- simple commands


def _by_sets(program: str) -> Extraction:
    for programs, effect in (
        (_DESTRUCTIVE_PROGRAMS, "destructive"),
        (_EXTERNAL_PROGRAMS, "external_comm"),
        (_WRITE_PROGRAMS, "write"),
        (_READ_PROGRAMS, "read"),
    ):
        if program in programs:
            return _found(effect, f"shell:{program}")  # type: ignore[arg-type]
    return Extraction()


def _arg_resources(program: str, args: list[str]) -> Extraction:
    positional = [a for a in args if not a.startswith("-")]
    if program in _OWNER_FIRST:
        positional = positional[1:]
    every = program in _FILE_PROGRAMS or program in _OWNER_FIRST
    refs = []
    for arg in positional:
        if "://" in arg:
            refs.extend(url_refs(arg))
        elif every or looks_like_path(arg):
            ref = path_ref(arg)
            if ref is not None:
                refs.append(ref)
    return Extraction(resources=tuple(refs))


_EXEC_VARS: Final = frozenset(
    {
        "GIT_SSH_COMMAND",
        "GIT_SSH",
        "GIT_EXTERNAL_DIFF",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "GIT_PROXY_COMMAND",
        "GIT_CONFIG_PARAMETERS",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "PERL5OPT",
        "NODE_OPTIONS",
        "GIT_PAGER",
        "PAGER",
        "GIT_EDITOR",
        "EDITOR",
        "VISUAL",
        "GIT_EXEC_PATH",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
    }
)
_EXEC_VAR_PREFIXES: Final = (
    "GIT_CONFIG_KEY_",
    "GIT_CONFIG_VALUE_",
    "LD_",  # LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT
    "DYLD_",
)
_EXEC_VAR_NAMES: Final = frozenset(
    {"PATH", "PYTHONPATH", "PYTHONHOME", "RUBYOPT", "RUBYLIB", "GCONV_PATH", "IFS"}
)


def _simple(argv: list[str], depth: int) -> Extraction:
    if depth > _MAX_DEPTH:
        return _found("destructive", "shell:too-deep")
    exec_env = Extraction()
    while argv:
        if _ASSIGNMENT.match(argv[0]):
            name = argv[0].split("=", 1)[0]
            if name in _EXEC_VARS | _EXEC_VAR_NAMES or name.startswith(_EXEC_VAR_PREFIXES):
                exec_env = _found("destructive", "shell:exec-env")
            argv = argv[1:]
            continue
        unwrap = _WRAPPERS.get(_program(argv[0]))
        if unwrap is None:
            break
        argv = unwrap(argv[1:])
    if not argv:
        return exec_env
    program, args = _program(argv[0]), argv[1:]
    handler = _HANDLERS.get(program)
    result = handler(args, depth) if handler else _by_sets(program)
    if result.effect == "read" and not _is_trusted_location(argv[0]):
        # A binary outside the system folders only borrows the name; never call it a read.
        result = Extraction(resources=result.resources)
    return result.merge(exec_env).merge(_arg_resources(program, args))


# ---------------------------------------------------------------- command lines


def _substitutions(command: str, depth: int) -> Extraction:
    """Classify ``$(...)``, ``<(...)``, ``>(...)`` and backtick bodies, quoted or not."""
    result = Extraction()
    bodies: dict[str, None] = {}
    i = 0
    while (match := _SUBSTITUTION.search(command, i)) is not None:
        # Only top-level bodies here; nested ones are found when the body is
        # classified, so every character is scanned once per nesting level.
        level, end = 1, match.end()
        while end < len(command) and level:
            level += {"(": 1, ")": -1}.get(command[end], 0)
            end += 1
        bodies[command[match.end() : end - 1 if not level else end]] = None
        i = end
    bodies.update(dict.fromkeys(command.split("`")[1::2]))
    for body in bodies:  # each distinct body once
        result = result.merge(_command(body, depth + 1))
    return result


def _tokens(command: str) -> list[str]:
    text = command.replace("\\\r\n", " ").replace("\\\n", " ")
    lexer = shlex.shlex(text, posix=True, punctuation_chars=_PUNCT)
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _is_operator(token: str) -> bool:
    return bool(token) and all(c in _PUNCT for c in token)


def _split(tokens: list[str]) -> list[tuple[list[str], Extraction]]:
    """Simple commands with the files their output redirections write."""
    commands: list[tuple[list[str], Extraction]] = []
    argv: list[str] = []
    redirects = Extraction()
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if not _is_operator(token):
            argv.append(token)
        elif ("<" in token or ">" in token) and not set(token) & set("();\n"):
            if argv and argv[-1].isdigit():
                argv.pop()  # 2>file
            target = (
                tokens[i + 1] if i + 1 < len(tokens) and not _is_operator(tokens[i + 1]) else None
            )
            if target is not None:
                i += 1
                if ">" in token and not target.isdigit() and target != "/dev/null":
                    ref = path_ref(target)
                    refs = (ref,) if ref is not None else ()
                    redirects = redirects.merge(Extraction(refs, "write", ("shell:redirect",)))
        else:
            commands.append((argv, redirects))
            argv, redirects = [], Extraction()
        i += 1
    commands.append((argv, redirects))
    return commands


def _command(command: str | Sequence[str], depth: int) -> Extraction:
    if depth > _MAX_DEPTH:
        return _found("destructive", "shell:too-deep")
    if not isinstance(command, str):
        return _simple(list(command), depth)
    if len(command) > _MAX_COMMAND:
        return _found("destructive", "shell:too-large")
    result = _substitutions(command, depth)
    try:
        tokens = _tokens(command)
    except ValueError:
        return result.raised("destructive", "shell:unparsed")
    for argv, redirects in _split(tokens):
        result = result.merge(_simple(argv, depth)).merge(redirects)
    return result


def classify_shell(command: str | Sequence[str]) -> Extraction:
    """Classify a command line, or an argv list that is run without a shell.

    Example:
        >>> classify_shell(["rm", "-rf", "/srv/app"]).effect
        'destructive'
    """
    return _command(command, 0).normalized()
