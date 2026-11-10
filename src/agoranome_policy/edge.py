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

"""Learning at the edge: the buyer's own delivery record, kept on its own machine.

A Guard given a receipt log (`Guard(..., receipts="~/.agoranome/receipts.jsonl")`) keeps a private Beta per pay-to
address from its own signed receipts: a settled payment answered 2xx at no more than the quoted or listed price
counts good, any other settled payment counts bad (a payment that didn't settle counts neither). It combines that
with Agoranome's delivery odds by precision weighting, the free checker's evidence capped at ten observations so
the buyer's own experience leads after about ten calls:

    a = good + n * p,   b = bad + n * (1 - p),   n = min(observations, 10), at least 1

where p is the free checker's delivery odds and observations its count. The combined odds are a / (a + b). With no
odds from Agoranome, a uniform prior stands in (a = good + 1, b = bad + 1); with no record of its own, the guard
uses Agoranome's odds as they are.

When offers tie on price, `Guard.choose` draws once from each one's Beta and tries them in the order of the draws
(Thompson sampling), so a seller that has served this buyer well is tried first more often, and a new one still
gets tried. Nothing here leaves the machine: telemetry never carries the record, and only receipts whose signature
checks are counted.
"""

import random
import threading
from typing import Any, Dict, Optional

CAP = 10.0   # Agoranome's evidence counts as at most this many observations


def outcome(line: Dict[str, Any]) -> Optional[bool]:
    """A receipt's outcome: True (a settled 2xx at no more than the price expected), False (any other settled
    payment), or None (it didn't settle, or says nothing)."""
    if line.get("settled") is not True:
        return None
    status = line.get("status")
    decision = line.get("decision") if isinstance(line.get("decision"), dict) else {}
    price, expected = decision.get("price_usd"), decision.get("expected_price_usd")
    over = (isinstance(price, (int, float)) and isinstance(expected, (int, float)) and price > expected + 1e-12)
    return isinstance(status, int) and 200 <= status < 300 and not over


def _pay_to(line: Dict[str, Any]) -> str:
    option = line.get("option") if isinstance(line.get("option"), dict) else {}
    return str(option.get("pay_to") or "").lower()


class OwnRecord:
    """Good and bad outcomes per pay-to, from a receipt log's signed lines and from each payment recorded since."""

    def __init__(self, receipts: Any = None):
        self.receipts = receipts
        self._counts: Dict[str, Dict[str, int]] = {}
        self._lock = threading.Lock()
        self.error: Optional[str] = None
        if receipts is not None:
            try:
                for line in receipts:
                    if receipts.verify(line):
                        self.add(line)
            except (OSError, ValueError) as e:   # an unreadable log leaves the record empty
                self.error = f"{type(e).__name__}: {e}"

    def add(self, line: Dict[str, Any]) -> None:
        found, pay_to = outcome(line), _pay_to(line)
        if found is None or not pay_to:
            return
        with self._lock:
            counts = self._counts.setdefault(pay_to, {"good": 0, "bad": 0})
            counts["good" if found else "bad"] += 1

    def counts(self, pay_to: str) -> Dict[str, int]:
        with self._lock:
            return dict(self._counts.get(pay_to.lower(), {"good": 0, "bad": 0}))

    def beta(self, pay_to: str, agoranome: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """The combined Beta for a pay-to: {p, a, b, own, agoranome}, or None with no record of its own."""
        own = self.counts(pay_to)
        if own["good"] + own["bad"] == 0:
            return None
        p = (agoranome or {}).get("p")
        if isinstance(p, (int, float)) and not isinstance(p, bool) and 0 <= p <= 1:
            seen = (agoranome or {}).get("observations")
            n = min(max(float(seen) if isinstance(seen, (int, float)) else 0.0, 1.0), CAP)
            a, b = own["good"] + n * float(p), own["bad"] + n * (1 - float(p))
            theirs: Optional[Dict[str, Any]] = {"p": float(p), "weight": round(n, 4)}
        else:
            a, b, theirs = own["good"] + 1.0, own["bad"] + 1.0, None
        return {"p": round(a / (a + b), 4), "a": round(a, 4), "b": round(b, 4), "own": own, "agoranome": theirs}

    def draw(self, pay_to: str, agoranome: Optional[Dict[str, Any]] = None,
             rng: Optional[random.Random] = None) -> float:
        """One draw from the pay-to's Beta (Agoranome's odds alone, as ten observations at most, with no record
        of its own; a uniform prior with neither)."""
        found = self.beta(pay_to, agoranome)
        if found is None:
            p = (agoranome or {}).get("p")
            if isinstance(p, (int, float)) and not isinstance(p, bool) and 0 <= p <= 1:
                seen = (agoranome or {}).get("observations")
                n = min(max(float(seen) if isinstance(seen, (int, float)) else 0.0, 1.0), CAP)
                a, b = 1.0 + n * float(p), 1.0 + n * (1 - float(p))
            else:
                a, b = 1.0, 1.0
        else:
            a, b = found["a"], found["b"]
        return (rng or random).betavariate(max(a, 1e-6), max(b, 1e-6))
