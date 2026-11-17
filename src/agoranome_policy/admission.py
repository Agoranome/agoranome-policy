# Copyright 2026 The Agoranome Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Agoranome's admission feed as an allowlist: the x402 sellers that meet published rules, by category.

    feed = AdmissionFeed.from_url()                        # https://api.agoranome.com/machines/admission.json
    policy = Policy("any", allow_pay_to=feed.payees())     # pay admitted sellers only
    wide = AdmissionFeed.from_url(tier="sheet")            # the same feed with the sheet tier added
    policy = Policy("any", allow_pay_to=wide.payees("sheet"))

Three tiers, all by rule and never sold, from the widest: "sheet" (on the Agoranome inspector's newest signed sheet,
every offer asked what its listing shows and paid an address the listing names, with no paid test; served only when
asked, ?tier=sheet), "observed" (Agoranome's own paid probe delivered, the live price and pay-to match the listing,
no OFAC match) and "certified" (observed, plus a Fair Offer certification passed in 30 days). Certification is no
longer sold, since Agoranome sells nothing to a seller it grades, so the certified tier empties as the last
certificates pass 30 days. A tier admits the tiers above it too.
The feed is signed (JWS over its RFC 8785 form, keys at /.well-known/jwks.json). Since 0.9.0 `from_url` checks the
signatures before it returns the feed, with the standard library's Ed25519 (referees.py), against keys read from the
feed's own site (a key set on another site is never read) or against keys you pin with `keys=`; a feed with no
signature that checks raises AdmissionError. Before 0.9.0 it loaded the feed unchecked. Read it again daily.
"""

import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from agoranome_policy.evidence import EvidenceError, urllib_get
from agoranome_policy.referees import JWKS_PATH, check, same_site

DEFAULT_URL = "https://api.agoranome.com/machines/admission.json"
SHEET, OBSERVED, CERTIFIED = "sheet", "observed", "certified"
_RANK = {SHEET: 0, OBSERVED: 1, CERTIFIED: 2}
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
Getter = Callable[[str], Tuple[int, bytes]]


class AdmissionError(ValueError):
    """The feed couldn't be read, or no signature on it checks."""


def _json(get: Getter, url: str) -> Any:
    try:
        status, body = get(url)
    except EvidenceError as e:
        raise AdmissionError(str(e)) from e
    if not 200 <= status < 300:
        raise AdmissionError(f"{url} answered {status}")
    try:
        return json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
    except (ValueError, UnicodeDecodeError) as e:
        raise AdmissionError(f"{url} didn't answer JSON") from e


def signatures(doc: Dict[str, Any], url: str, keys: Optional[List[Dict[str, Any]]] = None,
               get: Optional[Getter] = None) -> List[Dict[str, Any]]:
    """Each signature on a feed read from `url`, checked: {kid, alg, verified, why}. Without `keys`, the key set is
    read from the feed's `jwks` when that is on the feed's own site, else from the site's /.well-known/jwks.json."""
    if keys is None:
        parts = urlsplit(url)
        jwks = str(doc.get("jwks") or "")
        if not jwks or not same_site(jwks, url):
            jwks = f"https://{parts.netloc}{JWKS_PATH}"
        try:
            found = _json(get or urllib_get(10.0), jwks)
            keys = found.get("keys") if isinstance(found, dict) and isinstance(found.get("keys"), list) else []
        except AdmissionError:
            keys = []
    return check(doc, url, keys)


class AdmissionFeed:
    def __init__(self, data: Dict[str, Any], verified: Optional[bool] = None):
        if not isinstance(data, dict) or not isinstance(data.get("sellers"), list):
            raise ValueError("not an Agoranome admission feed")
        self.data = data
        self.verified = verified   # True when from_url checked a signature; None when the feed was handed in
        self.sellers: Dict[str, Dict[str, Any]] = {str(s.get("host") or "").lower(): s for s in data["sellers"]
                                                   if isinstance(s, dict) and s.get("host")}

    @classmethod
    def from_url(cls, url: str = DEFAULT_URL, timeout: float = 10.0, tier: Optional[str] = None, *,
                 verify: bool = True, keys: Optional[List[Dict[str, Any]]] = None,
                 get: Optional[Getter] = None) -> "AdmissionFeed":
        """The feed, its signature checked; tier="sheet" asks for it with the sheet tier added. `keys` pins the
        signing keys (a JWKS's "keys"); verify=False skips the check (not advised: the feed becomes a wallet's
        allowlist). Raises AdmissionError when no signature checks."""
        if tier is not None and tier not in _RANK:
            raise ValueError("tier must be sheet, observed or certified")
        if urlsplit(url).scheme != "https":
            raise AdmissionError("the admission feed is read over https only")
        if tier == SHEET:
            url += ("&" if "?" in url else "?") + "tier=sheet"
        get = get or urllib_get(timeout)
        doc = _json(get, url)
        if not isinstance(doc, dict):
            raise AdmissionError("not an Agoranome admission feed")
        if not verify:
            return cls(doc, verified=False)
        checked = signatures(doc, url, keys, get)
        if not any(s.get("verified") is True for s in checked):
            why = "; ".join(sorted({str(s.get("why")) for s in checked if s.get("why")})) or "it carries none"
            raise AdmissionError(f"no signature on the admission feed checks ({why})")
        return cls(doc, verified=True)

    @property
    def day(self) -> Optional[str]:
        return self.data.get("day")

    def tier_of(self, host_or_url: str) -> Optional[str]:
        host = (urlsplit(host_or_url).hostname or host_or_url) if "://" in host_or_url else host_or_url
        seller = self.sellers.get((host or "").rstrip(".").lower())
        return seller.get("tier") if seller else None

    def _meets(self, seller: Dict[str, Any], tier: str) -> bool:
        if tier not in _RANK:
            raise ValueError("tier must be sheet, observed or certified")
        return _RANK.get(seller.get("tier"), -1) >= _RANK[tier]

    def payees(self, tier: str = OBSERVED, network: str = "eip155:8453") -> List[str]:
        """Every pay-to address on `network` of a seller admitted at `tier` or above, lowercased."""
        out = set()
        for seller in self.sellers.values():
            if not self._meets(seller, tier):
                continue
            if network not in (seller.get("networks") or [network]):
                continue
            out.update(p.lower() for p in seller.get("pay_to") or [] if isinstance(p, str) and _ADDRESS.match(p))
        return sorted(out)

    def admits(self, pay_to: str, *, host: Optional[str] = None, tier: str = OBSERVED) -> bool:
        """Whether a payment to `pay_to` (at `host`, when given) goes to an admitted seller of `tier` or better."""
        pay_to = (pay_to or "").lower()
        for name, seller in self.sellers.items():
            if host is not None and name != host.lower():
                continue
            if not self._meets(seller, tier):
                continue
            if pay_to in {p.lower() for p in seller.get("pay_to") or []}:
                return True
        return False

    def in_category(self, category: str, tier: str = OBSERVED) -> List[str]:
        """The admitted hosts in one category, by host (the feed never ranks them)."""
        return sorted(h for h, s in self.sellers.items() if category in (s.get("categories") or [])
                      and self._meets(s, tier))
