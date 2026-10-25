"""Email recipients.

Accepts ``"Bob <bob@example.com>, carol@example.org"`` and lists of addresses.
Each valid address becomes an ``email`` resource with its domain as an
attribute, so a policy can tag internal and external domains.

Example:
    >>> [(r.uri, r.attrs) for r in email_refs("Bob <Bob@Example.com>")]
    [('bob@example.com', {'domain': 'example.com'})]
"""

from __future__ import annotations

import re
from email.utils import parseaddr
from typing import TYPE_CHECKING, Final

from arbitr.resources.base import make_ref

if TYPE_CHECKING:
    from arbitr.core.spec import ResourceRef

_ADDRESS: Final = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


_ANY_ADDRESS: Final = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}"
)
UNPARSED: Final = "unparsed"
"""URI and domain of a recipient that is not a valid address. Fails closed:
policies that trust certain domains never trust an unparsed recipient."""


def email_refs(value: str) -> list[ResourceRef]:
    """Resources for every recipient, plus one ``unparsed`` resource if any part is invalid."""
    refs: list[ResourceRef] = []
    unparsed = False
    for part in re.split(r"[,;\n]", value):
        if not part.strip():
            continue
        _, address = parseaddr(part)
        addr = address.strip().lower()
        tokens = {t.lower() for t in _ANY_ADDRESS.findall(part)}
        found = sorted(tokens | ({addr} if _ADDRESS.match(addr) else set()))
        refs.extend(make_ref("email", t, {"domain": t.rsplit("@", 1)[1]}) for t in found)
        if not _ADDRESS.match(addr) or tokens - {addr}:
            unparsed = True  # invalid, or more than one address hiding in one part
    if unparsed:
        refs.append(make_ref("email", UNPARSED, {"domain": UNPARSED}))
    return refs
