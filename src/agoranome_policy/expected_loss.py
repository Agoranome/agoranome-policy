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

"""Expected-loss mode: pay for evidence only when the loss it could prevent is worth more than it costs.

Beside the fixed tiers (any, sampled, delivered), a buyer can decide each payment by value of information:

  1. Start from the category's prior chance of loss (a payment that buys nothing usable, or costs more than
     listed), from Agoranome's free "Base rates by category" dataset (/machines/base-rates.json).
  2. Update it with the seller's own evidence, as a beta-binomial: the prior counts as PRIOR_WEIGHT observations,
     and each piece of evidence adds good or bad ones. An admission-feed tier (observed, certified), a sample
     the free checker verified, and verified deliveries in 30 days count as good; a contradicted Fair Offer rule
     counts as bad.
  3. When Agoranome's free checker gives the seller's delivery odds (a posterior from probes, reconciled
     deliveries, returning buyers and settlement proofs, each forgotten by age), the chance of loss is the larger
     of 1 - p and the posterior above: the odds can only add caution here, never take it away.
  4. Expected loss = price x the posterior chance of loss.

Then: refuse when the posterior chance of loss is at or above refuse_above (default 0.5); pay when the expected
loss is no more than the cost of a check (default $0.01, Agoranome's signed Buyer check); otherwise check first,
because the check costs less than the loss it can prevent. A $0.005 chain read from an observed seller needs
nothing; a $1 panel run from an unseen host is worth a $0.01 check first.

No dependencies beyond the standard library.
"""

import json
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

PAY, CHECK_FIRST, REFUSE = "pay", "check_first", "refuse"
DEFAULT_URL = "https://api.agoranome.com/machines/base-rates.json"
DEFAULT_PRIOR = 0.2      # only while the dataset has no prior: deliberately cautious, and the decision says so
PRIOR_WEIGHT = 10.0      # the prior counts as this many observations
EVIDENCE_WEIGHTS = {"observed": 3.0, "certified": 6.0, "sampled": 1.0, "delivery": 1.0, "contradicted": 8.0}
MAX_DELIVERIES = 30      # deliveries counted, at most


@dataclass
class Evidence:
    """What is known about one seller before paying it."""

    tier: Optional[str] = None       # its admission-feed tier: "observed", "certified" or None
    sampled: bool = False            # the free checker fetched its declared sample and it matched
    deliveries_30d: int = 0          # verified deliveries to wallets that aren't sweeps, in 30 days
    contradicted: bool = False       # a Fair Offer rule was contradicted

    def counts(self) -> Dict[str, float]:
        good = EVIDENCE_WEIGHTS.get(self.tier or "", 0.0)
        good += EVIDENCE_WEIGHTS["sampled"] if self.sampled else 0.0
        good += EVIDENCE_WEIGHTS["delivery"] * min(max(int(self.deliveries_30d or 0), 0), MAX_DELIVERIES)
        bad = EVIDENCE_WEIGHTS["contradicted"] if self.contradicted else 0.0
        return {"good": good, "bad": bad}


@dataclass
class LossDecision:
    action: str
    price_usd: float
    prior: float
    prior_source: str
    posterior: float
    expected_loss_usd: float
    check_cost_usd: float
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def summary(self) -> str:
        loss = f"expected loss ${self.expected_loss_usd:.4f} (chance {self.posterior:.1%})"
        if self.action == PAY:
            return f"Pay: {loss} is no more than a ${self.check_cost_usd:g} check."
        if self.action == CHECK_FIRST:
            return f"Check first: {loss} is more than a ${self.check_cost_usd:g} check."
        return f"Refuse: the chance of loss, {self.posterior:.1%}, is too high."

    def as_dict(self) -> Dict[str, Any]:
        return {"action": self.action, "price_usd": self.price_usd, "prior": self.prior,
                "prior_source": self.prior_source, "posterior": round(self.posterior, 6),
                "expected_loss_usd": round(self.expected_loss_usd, 6), "check_cost_usd": self.check_cost_usd,
                "evidence": self.evidence, "summary": self.summary}


class BaseRates:
    """The dataset's prior chance of loss by category, the pooled one for a category it doesn't list."""

    def __init__(self, data: Dict[str, Any]):
        self.data = data
        rows = list(data.get("categories") or [])
        self.by_key = {r.get("key"): r for r in rows if isinstance(r, dict)}
        self.pooled = data.get("all") or {}

    @classmethod
    def from_url(cls, url: str = DEFAULT_URL, timeout: float = 10.0) -> "BaseRates":
        request = urllib.request.Request(url, headers={"Accept": "application/json",
                                                       "User-Agent": "agoranome-policy"})
        with urllib.request.urlopen(request, timeout=timeout) as response:   # noqa: S310 (https by default)
            return cls(json.loads(response.read().decode("utf-8")))

    def prior(self, category: Optional[str]) -> Optional[float]:
        row = self.by_key.get(category) if category else None
        for candidate in (row, self.pooled):
            value = ((candidate or {}).get("prior_loss") or {}).get("value")
            if isinstance(value, (int, float)) and 0 <= value <= 1:
                return float(value)
        return None


class ExpectedLoss:
    """Decide one payment by expected loss. `base_rates` is a BaseRates (or None: DEFAULT_PRIOR for every
    category); `admission` an admission.AdmissionFeed whose tiers count as evidence (or None)."""

    def __init__(self, base_rates: Optional[BaseRates] = None, *, admission: Any = None, check_cost_usd: float = 0.01,
                 refuse_above: float = 0.5, default_prior: float = DEFAULT_PRIOR):
        if not 0 < refuse_above <= 1:
            raise ValueError("refuse_above must be in (0, 1]")
        self.base_rates = base_rates
        self.admission = admission
        self.check_cost_usd = float(check_cost_usd)
        self.refuse_above = float(refuse_above)
        self.default_prior = float(default_prior)

    def prior(self, category: Optional[str]) -> tuple:
        found = self.base_rates.prior(category) if self.base_rates is not None else None
        return (found, "base rates") if found is not None else (self.default_prior, "default")

    @staticmethod
    def posterior(prior: float, evidence: Evidence) -> float:
        counts = evidence.counts()
        bad = prior * PRIOR_WEIGHT + counts["bad"]
        good = (1 - prior) * PRIOR_WEIGHT + counts["good"]
        return bad / (bad + good)

    def decide(self, price_usd: float, *, category: Optional[str] = None, evidence: Optional[Evidence] = None,
               host: Optional[str] = None, delivery_odds: Optional[Dict[str, Any]] = None) -> LossDecision:
        evidence = evidence or Evidence()
        if evidence.tier is None and host and self.admission is not None:
            evidence.tier = self.admission.tier_of(host)
        prior, source = self.prior(category)
        chance = self.posterior(prior, evidence)
        odds = (delivery_odds or {}).get("p")
        from_odds = isinstance(odds, (int, float)) and not isinstance(odds, bool) and 0.0 <= odds <= 1.0
        if from_odds:
            chance = max(chance, 1.0 - float(odds))
        loss = float(price_usd) * chance
        if chance >= self.refuse_above - 1e-12:
            action = REFUSE
        elif loss <= self.check_cost_usd + 1e-12:
            action = PAY
        else:
            action = CHECK_FIRST
        shown: Dict[str, Any] = {"tier": evidence.tier, "sampled": evidence.sampled,
                                 "deliveries_30d": evidence.deliveries_30d, "contradicted": evidence.contradicted}
        if from_odds:
            shown["delivery_odds"] = float(odds)
        return LossDecision(action=action, price_usd=float(price_usd), prior=prior, prior_source=source,
                            posterior=chance, expected_loss_usd=loss, check_cost_usd=self.check_cost_usd,
                            evidence=shown)


def evidence_from_rules(rules: Dict[str, Any], deliveries_30d: Optional[int] = None,
                        tier: Optional[str] = None) -> Evidence:
    """Evidence from the free checker's rules (FO-1..FO-7, each {"status": ...}) and delivery count."""
    def status(rule: Any) -> str:
        return str((rule or {}).get("status") if isinstance(rule, dict) else rule or "")

    statuses: List[str] = [status(r) for r in (rules or {}).values()]
    return Evidence(tier=tier, sampled=status((rules or {}).get("FO-4")) == "verified",
                    deliveries_30d=int(deliveries_30d or 0), contradicted="contradicted" in statuses)
