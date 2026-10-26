"""Approvals for people: readable cards, signed links, a webhook channel and analytics.

An approval request is bound to one intent hash and one attempt, so a decision
can never authorize different arguments. Approvers decide through
``Ledger.approve`` and ``Ledger.reject``, or with a signed link.

Signed links carry the approval id, the approver, their roles and the decision,
with an HMAC over those and the approval's intent hash and expiry. A link
cannot be moved to another approval, outlives nothing (it expires with the
request) and works once, because an approver votes once.

The webhook channel POSTs the card and one pair of signed links per approver
to a URL. It is best effort: a failing webhook never blocks or fails the call.

Analytics count requests and decisions per rule and flag rules people
approve almost every time without thinking (rubber stamps), which are better
written as allow rules or tightened.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import statistics
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol
from urllib.parse import quote, urlsplit

from arbitr.core.errors import ApprovalError
from arbitr.storage.sqlite import parse_db_time

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from arbitr.executor import Ledger
    from arbitr.storage.sqlite import ApprovalRow

__all__ = [
    "ApprovalNotifier",
    "LinkClaim",
    "RuleStats",
    "WebhookNotifier",
    "approval_stats",
    "clean_text",
    "link_token",
    "quote_text",
    "read_link",
]

_LINK_CONTEXT: Final = b"arbitr approval links v1"
RUBBER_STAMP_RATE: Final = 0.98
RUBBER_STAMP_SECONDS: Final = 3.0
RUBBER_STAMP_MIN_DECISIONS: Final = 20


# ---------------------------------------------------------------- signed links


@dataclass(frozen=True)
class LinkClaim:
    """What a signed link says: who decides what on which approval."""

    approval_id: str
    approver: str
    roles: tuple[str, ...]
    decision: str


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _mac(key: bytes, claim: LinkClaim, approval: ApprovalRow) -> str:
    link_key = hmac.new(key, _LINK_CONTEXT, hashlib.sha256).digest()
    message = json.dumps(
        [claim.approval_id, claim.approver, sorted(claim.roles), claim.decision,
         approval.intent_hash, approval.expires_at],
        separators=(",", ":"),
    )  # fmt: skip
    return _b64(hmac.new(link_key, message.encode(), hashlib.sha256).digest())


def link_token(key: bytes, approval: ApprovalRow, claim: LinkClaim) -> str:
    """A token for one approver's decision on one approval, signed with the ledger key."""
    if claim.approval_id != approval.approval_id:
        raise ApprovalError("a link must name the approval it is signed for")
    if claim.decision not in ("approve", "reject"):
        raise ApprovalError(f"a link decides approve or reject, not {claim.decision!r}")
    who = _b64(json.dumps([claim.approver, sorted(claim.roles)]).encode())
    return f"{claim.approval_id}.{claim.decision}.{who}.{_mac(key, claim, approval)}"


def read_link(token: str) -> tuple[LinkClaim, str]:
    """The claim and signature in a token, unchecked. Raises ApprovalError if malformed."""
    try:
        approval_id, decision, who, mac = token.strip().split(".")
        approver, roles = json.loads(_unb64(who))
    except (ValueError, TypeError) as exc:
        raise ApprovalError("this approval link is malformed") from exc
    if not isinstance(approver, str) or not isinstance(roles, list):
        raise ApprovalError("this approval link is malformed")
    return LinkClaim(approval_id, approver, tuple(str(r) for r in roles), decision), mac


def check_link(key: bytes, token: str, approval: ApprovalRow) -> LinkClaim:
    """The claim of a token whose signature matches this approval, or ApprovalError."""
    claim, mac = read_link(token)
    if claim.approval_id != approval.approval_id or not hmac.compare_digest(
        mac, _mac(key, claim, approval)
    ):
        raise ApprovalError("this approval link's signature does not match")
    return claim


def link_url(base_url: str, token: str) -> str:
    """The URL an approver opens, for example on a phone."""
    return f"{base_url.rstrip('/')}/approvals/decide?token={quote(token, safe='.')}"


# ---------------------------------------------------------------- cards


def card_text(card: Mapping[str, object]) -> str:
    """The card in a few plain sentences, for chat messages and the terminal.

    Values that came from the agent (arguments, resources, the task) are put
    on one line each, quoted, with control characters removed, so they cannot
    forge a line of their own such as a fake rule.
    """
    head = f"{clean_text(card['tool'])} ({clean_text(card['effect'])})"
    lines = [f"{head}: {_short_args(card.get('args'))}"]
    if card.get("truncated"):
        lines.append(
            "ARGUMENTS CUT: some values are shortened here. Read them in full"
            " (arbitr approvals show <id> --json, field args_full) before approving."
        )
    lines.append(f"Rule {clean_text(card['rule'])}: {clean_text(card['reason'])}")
    resources = card.get("resources") or []
    if isinstance(resources, list) and resources:
        shown = ", ".join(_resource_text(r) for r in resources[:5] if isinstance(r, dict))
        more = f" and {len(resources) - 5} more" if len(resources) > 5 else ""  # noqa: PLR2004
        lines.append(f"Touches {shown}{more}.")
    preview = card.get("preview")
    if isinstance(preview, dict):
        if preview.get("ok"):
            lines.append(f"Preview: {clean_text(preview.get('summary'))}")
        else:
            failed = clean_text(preview.get("summary"))
            lines.append(
                f"PREVIEW FAILED: {failed}. The stricter decision was applied;"
                " check the impact yourself before approving."
            )
    if card.get("task"):
        lines.append(f"Task: {quote_text(card['task'])}")
    taint = card.get("taint") or {}
    if isinstance(taint, dict) and any(taint.values()):
        read = [name.replace("_", " ") for name, on in taint.items() if on]
        lines.append(f"The run has read {' and '.join(read)}.")
    if card.get("outside_scope"):
        lines.append("This action is outside the scope declared for the run.")
    return "\n".join(lines)


_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f\u2028\u2029]+")
_CLEAN_LIMIT: Final = 200


def clean_text(value: object) -> str:
    """One line of text for a person to read: control characters become spaces, long text is cut."""
    text = " ".join(_CONTROL.sub(" ", str(value)).split())
    return text if len(text) <= _CLEAN_LIMIT else text[:_CLEAN_LIMIT] + "..."


def quote_text(value: object) -> str:
    """The value cleaned with clean_text and quoted, so it reads as data."""
    return json.dumps(clean_text(value), ensure_ascii=False)


def _short_args(args: object) -> str:
    if not isinstance(args, dict) or not args:
        return "no arguments"
    return ", ".join(f"{clean_text(k)}={quote_text(v)}" for k, v in list(args.items())[:6])


def _resource_text(resource: Mapping[str, object]) -> str:
    tags = resource.get("tags")
    names = [clean_text(t) for t in tags] if isinstance(tags, list) else []
    tagged = f" [{', '.join(names)}]" if names else ""
    return f"{clean_text(resource.get('kind'))} {quote_text(resource.get('uri'))}{tagged}"


# ---------------------------------------------------------------- webhook channel


class ApprovalNotifier(Protocol):
    """Tells people that an approval is waiting. Must not raise for delivery problems."""

    def notify(self, ledger: Ledger, approval: ApprovalRow, card: Mapping[str, object]) -> None:
        """Deliver one approval request."""
        ...


class WebhookNotifier:
    """POSTs each approval card as JSON, with signed links where that is safe.

    A link is a bearer token: whoever holds it votes as the approver it names.
    So each approver's links go only to that approver's own URL
    (``approver_urls``). The shared ``url`` gets the card, and links only
    when one approval from anyone is enough (no roles, no separation from the
    principal), since then every reader of the channel may decide anyway.
    Nobody gets links for an approval they may not give: the principal the
    agent acts for, or someone without a required role.
    """

    def __init__(
        self,
        url: str,
        *,
        link_base_url: str,
        approvers: Mapping[str, Sequence[str]] | None = None,
        approver_urls: Mapping[str, str] | None = None,
        timeout: float = 2.0,
    ) -> None:
        """Send to ``url``; ``approvers`` maps approver names to their roles."""
        for target in (url, *(approver_urls or {}).values()):
            _check_webhook_url(target)
        self.url = url
        self.link_base_url = link_base_url
        self.approvers = {name: tuple(roles) for name, roles in (approvers or {}).items()}
        self.approver_urls = dict(approver_urls or {})
        self.timeout = timeout

    def notify(self, ledger: Ledger, approval: ApprovalRow, card: Mapping[str, object]) -> None:
        """POST the card. Delivery errors are swallowed: the approval is already recorded."""
        eligible = {n: r for n, r in self.approvers.items() if _may_approve(approval, n, r)}

        def links(name: str, roles: tuple[str, ...]) -> dict[str, str]:
            return ledger.approval_links(approval.approval_id, approver=name, roles=roles,
                                         base_url=self.link_base_url)  # fmt: skip

        for name, roles in eligible.items():
            if name in self.approver_urls:
                self._post(self.approver_urls[name], card, {name: links(name, roles)})
        # On the shared channel every reader could use the links, so they go
        # there only when anyone at all may give the approval alone.
        open_to_all = (
            approval.required == 1
            and not approval.allowed_roles()
            and approval.separate_from is None
        )
        shared = (
            {n: links(n, r) for n, r in eligible.items() if n not in self.approver_urls}
            if open_to_all
            else {}
        )
        self._post(self.url, card, shared)

    def _post(self, url: str, card: Mapping[str, object], links: Mapping[str, object]) -> None:
        body = json.dumps({"card": dict(card), "links": dict(links)}).encode()
        request = urllib.request.Request(  # noqa: S310  # nosec B310
            url, data=body, method="POST", headers={"Content-Type": "application/json"}
        )
        try:
            # Schemes are limited to http and https in __init__.
            with urllib.request.urlopen(request, timeout=self.timeout):  # noqa: S310  # nosec B310
                pass
        except OSError:
            return  # best effort; the request stays visible in `arbitr approvals ls`


_LOOPBACK: Final = frozenset({"127.0.0.1", "localhost", "::1"})


def _check_webhook_url(url: str) -> None:
    """Webhook messages carry bearer links, so they go over https (http only on this machine)."""
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and parts.hostname in _LOOPBACK:
        return
    raise ApprovalError("a webhook URL must use https (http only for 127.0.0.1 or localhost)")


def _may_approve(approval: ApprovalRow, name: str, roles: Sequence[str]) -> bool:
    if approval.separate_from is not None and name == approval.separate_from:
        return False
    allowed = approval.allowed_roles()
    return not allowed or bool(set(roles) & set(allowed))


# ---------------------------------------------------------------- analytics


@dataclass(frozen=True)
class RuleStats:
    """How people decide on one rule's approval requests."""

    rule_id: str
    requested: int
    approved: int
    rejected: int
    expired: int
    pending: int
    approval_rate: float
    """Approved out of decided (approved plus rejected); 0 when nothing was decided."""
    median_seconds: float | None
    """Median time from request to decision."""
    rubber_stamp: bool
    suggestion: str


def approval_stats(ledger: Ledger) -> list[RuleStats]:
    """Approval counts, rates and time to decision per rule, with rubber-stamp detection."""
    by_rule: dict[str, list[ApprovalRow]] = {}
    for approval in ledger.approvals():
        by_rule.setdefault(approval.rule_id or "unknown", []).append(approval)
    return [_rule_stats(rule_id, rows) for rule_id, rows in sorted(by_rule.items())]


def _rule_stats(rule_id: str, rows: list[ApprovalRow]) -> RuleStats:
    count = {s: sum(1 for r in rows if r.status == s) for s in ("approved", "rejected", "expired")}
    decided = count["approved"] + count["rejected"]
    rate = count["approved"] / decided if decided else 0.0
    times = [
        (parse_db_time(r.decided_at) - parse_db_time(r.requested_at)).total_seconds()
        for r in rows
        if r.decided_at is not None and r.status in ("approved", "rejected")
    ]
    median = statistics.median(times) if times else None
    stamp = (
        decided >= RUBBER_STAMP_MIN_DECISIONS
        and rate >= RUBBER_STAMP_RATE
        and median is not None
        and median < RUBBER_STAMP_SECONDS
    )
    suggestion = (
        f"People approve {rate:.0%} of these in a median of {median:.1f}s: write an allow"
        " rule for the safe cases, or tighten the rule so it asks only when it matters."
        if stamp and median is not None
        else ""
    )
    pending = sum(1 for r in rows if r.status == "pending")
    return RuleStats(rule_id, len(rows), count["approved"], count["rejected"],
                     count["expired"], pending, rate, median, stamp, suggestion)  # fmt: skip
