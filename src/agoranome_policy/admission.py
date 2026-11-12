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
The feed is signed (JWS over its RFC 8785 form, keys at /.well-known/jwks.json); this module reads it and leaves
checking the signatures to a JOSE library, since the pack has no dependencies. Read it again daily.
"""

import json
import re
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

DEFAULT_URL = "https://api.agoranome.com/machines/admission.json"
SHEET, OBSERVED, CERTIFIED = "sheet", "observed", "certified"
_RANK = {SHEET: 0, OBSERVED: 1, CERTIFIED: 2}
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


class AdmissionFeed:
    def __init__(self, data: Dict[str, Any]):
        if not isinstance(data, dict) or not isinstance(data.get("sellers"), list):
            raise ValueError("not an Agoranome admission feed")
        self.data = data
        self.sellers: Dict[str, Dict[str, Any]] = {str(s.get("host") or "").lower(): s for s in data["sellers"]
                                                   if isinstance(s, dict) and s.get("host")}

    @classmethod
    def from_url(cls, url: str = DEFAULT_URL, timeout: float = 10.0, tier: Optional[str] = None) -> "AdmissionFeed":
        """The feed; tier="sheet" asks for it with the sheet tier added."""
        if tier is not None and tier not in _RANK:
            raise ValueError("tier must be sheet, observed or certified")
        if tier == SHEET:
            url += ("&" if "?" in url else "?") + "tier=sheet"
        request = urllib.request.Request(url, headers={"Accept": "application/json",
                                                       "User-Agent": "agoranome-policy"})
        with urllib.request.urlopen(request, timeout=timeout) as response:   # noqa: S310 (https by default)
            return cls(json.loads(response.read().decode("utf-8")))

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
