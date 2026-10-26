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

"""The opt-in paid step: buy Agoranome's signed Buyer check ($0.01) before paying a seller.

Off unless the operator builds a PaidCheck and hands it to the Policy. When it is
on, the policy buys one check when the free check left the seller unknown (no
checker, or no verified deliveries on record), or when the offer's price is above
the operator's threshold, or always, as configured. A daily cap bounds the spend.

The pack has no dependencies, so paying is the operator's x402 client: `pay(url)`
is any callable that performs the paid GET and returns the JSON body (a dict, or
JSON as str or bytes). For example, with the x402 Python SDK's httpx client:

    from x402.http.clients.httpx import x402HttpxClient
    paying = x402HttpxClient(account=my_account)
    policy = Policy("sampled", checker=True,
                    paid_check=PaidCheck(lambda url: paying.get(url).json(), when="unknown_or_above",
                                         above_usd=0.10, daily_cap_usd=0.05))

The verdict is data about one offer, signed by Agoranome; the policy refuses when
it says the buyer's tier is not met or a Fair Offer rule is contradicted, and
flags a pay-to that changed in the last 30 days.
"""

import json
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlencode

from agoranome_policy.evidence import DEFAULT_BASE

CHECK_PATH = "/v1/buyer/check"
PRICE_USD = 0.01
WHEN = ("unknown", "above", "unknown_or_above", "always")


class PaidCheckError(Exception):
    """The paid check couldn't be bought or read. The policy goes on without it and says so."""


class PaidCheck:
    """When and how the policy buys Agoranome's signed Buyer check.

    pay            a callable that performs the paid GET of a URL and returns its JSON body
    base_url       Agoranome's API base
    when           "unknown" (seller unknown to the free check), "above" (price above above_usd),
                   "unknown_or_above" (default), or "always"
    above_usd      the price from which "above" applies (default $0.10)
    daily_cap_usd  never spend more than this on checks per UTC day (default $0.05, five checks)
    """

    def __init__(self, pay: Callable[[str], Any], *, base_url: str = DEFAULT_BASE, when: str = "unknown_or_above",
                 above_usd: float = 0.10, daily_cap_usd: float = 0.05, clock: Callable[[], float] = time.time):
        if when not in WHEN:
            raise ValueError(f"when must be one of {', '.join(WHEN)}")
        self.pay = pay
        self.base_url = base_url.rstrip("/")
        self.when = when
        self.above_usd = float(above_usd)
        self.daily_cap_usd = float(daily_cap_usd)
        self.clock = clock
        self._day: Optional[int] = None
        self._spent_usd = 0.0

    # --- when -------------------------------------------------------------------------

    def _today(self) -> int:
        return int(self.clock() // 86_400)

    @property
    def spent_today_usd(self) -> float:
        return self._spent_usd if self._day == self._today() else 0.0

    def within_cap(self) -> bool:
        return self.spent_today_usd + PRICE_USD <= self.daily_cap_usd + 1e-12

    def wanted(self, price_usd: Optional[float], *, unknown: bool) -> bool:
        """Whether this payment calls for a check (the cap is checked separately)."""
        if self.when == "always":
            return True
        above = price_usd is not None and price_usd > self.above_usd + 1e-12
        if self.when == "unknown":
            return unknown
        if self.when == "above":
            return above
        return unknown or above

    # --- buying ------------------------------------------------------------------------

    def url(self, offer_url: str, *, accept_proof: Optional[str] = None, max_price_usd: Optional[float] = None,
            expected_price_usd: Optional[float] = None) -> str:
        params: Dict[str, Any] = {"url": offer_url}
        if accept_proof:
            params["accept_proof"] = accept_proof
        if max_price_usd is not None:
            params["max_price"] = f"{max_price_usd:g}"
        if expected_price_usd is not None:
            params["expected_price"] = f"{expected_price_usd:g}"
        return f"{self.base_url}{CHECK_PATH}?{urlencode(params)}"

    def verdict(self, offer_url: str, **kwargs: Any) -> Dict[str, Any]:
        """Buy one verdict. Returns the result (the signed body's `result`); raises PaidCheckError."""
        try:
            body = self.pay(self.url(offer_url, **kwargs))
        except Exception as e:   # the operator's client: network, wallet, a refused payment
            raise PaidCheckError(f"the paid check couldn't be bought: {e}") from e
        if isinstance(body, (str, bytes)):
            try:
                body = json.loads(body)
            except ValueError as e:
                raise PaidCheckError("the paid check didn't answer JSON") from e
        if not isinstance(body, dict):
            raise PaidCheckError("the paid check didn't answer a JSON object")
        today = self._today()
        if self._day != today:
            self._day, self._spent_usd = today, 0.0
        self._spent_usd += PRICE_USD
        result = body.get("result") if isinstance(body.get("result"), dict) else body
        if "policy" not in result and "summary" not in result:
            raise PaidCheckError("the paid check's answer has no verdict")
        return result

    # --- reading -----------------------------------------------------------------------

    @staticmethod
    def refusals(verdict: Dict[str, Any], tier: str) -> List[str]:
        """Why the verdict says not to pay, for the buyer's tier."""
        out = []
        tiers = (verdict.get("policy") or {}).get("tiers") or {}
        if tiers.get(tier) is False:
            reasons = ((verdict.get("policy") or {}).get("reasons") or {}).get(tier) or []
            out.append(f"Agoranome's signed check says the offer fails the {tier} tier"
                       + (f" ({', '.join(str(r) for r in reasons)})" if reasons else ""))
        contradicted = ((verdict.get("fair_offer") or {}).get("rules") or {}).get("contradicted") or 0
        if contradicted:
            out.append(f"Agoranome's signed check found {contradicted} Fair Offer rule(s) contradicted")
        return out

    @staticmethod
    def flags(verdict: Dict[str, Any]) -> List[str]:
        """Worth knowing either way."""
        out = []
        pay_to = verdict.get("pay_to") or {}
        if pay_to.get("changed_30d"):
            out.append("Agoranome's signed check saw more than one pay-to address for this host in 30 days")
        certification = (verdict.get("certification") or {}).get("status")
        if certification in ("failed", "failing", "expired"):
            out.append(f"Agoranome's signed check: the seller's certification is {certification}")
        return out
