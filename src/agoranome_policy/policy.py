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

"""The policy: whether to pay an x402 offer, and why.

A decision runs five checks on the offer the buyer is about to pay:

1. A usable option: a network the buyer pays on, priced in USDC so the price can be read.
2. Price: no more than the buyer's cap, and no more than the listing or the quote.
3. Payee: on the buyer's allowlist, when there is one.
4. Instructions: no text in the offer written to steer an agent.
5. Proof: the buyer's tier (any, sampled or delivered), read from Agoranome's free
   checker when it's on, otherwise from what the seller's own block declares.

An optional sixth, off unless the operator turns it on (see paid.py): buy
Agoranome's signed Buyer check ($0.01) when the seller is unknown or the price is
above a threshold, and refuse when it says the tier is not met.

Raw payer counts are never used. Sweep bots pay every seller once, so a high
payer count says nothing about delivery; "delivered" counts verified
deliveries to wallets that aren't sweeps, from the evidence commons.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from agoranome_policy import proof
from agoranome_policy.evidence import EvidenceClient, EvidenceError
from agoranome_policy.instructions import instruction_like
from agoranome_policy.offer import Offer, Option
from agoranome_policy.paid import PaidCheck, PaidCheckError
from agoranome_policy.receipts import ReceiptLog

logger = logging.getLogger("agoranome_policy")

DEFAULT_MAX_PRICE_USD = 1.0   # default x402 clients refuse anything above $1
CAPTURE_SCHEME = "auth-capture"

# Reason codes. Telemetry reports these, never free text.
NO_OPTION = "no_usable_option"
NOT_USDC = "price_not_readable"
OVER_CAP = "over_cap"
OVER_EXPECTED = "over_listing_or_quote"
PAYEE = "payee_not_allowed"
INSTRUCTIONS = "instruction_like_text"
PROOF = "proof_unmet"
PAID_CHECK = "paid_check_refused"
REASONS = (NO_OPTION, NOT_USDC, OVER_CAP, OVER_EXPECTED, PAYEE, INSTRUCTIONS, PROOF, PAID_CHECK)


@dataclass
class Decision:
    """Whether to pay one offer. `reasons` are why not; `flags` are worth knowing either way."""

    allowed: bool
    url: str
    tier: str
    option: Optional[Option] = None
    price_usd: Optional[float] = None
    expected_price_usd: Optional[float] = None
    reasons: List[Dict[str, str]] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    requirements: List[str] = field(default_factory=list)
    unmet: List[Dict[str, str]] = field(default_factory=list)
    rules_source: str = "declared"
    category: Optional[str] = None
    paid_check: Optional[Dict[str, Any]] = None

    @property
    def accept_proof(self) -> Optional[str]:
        return proof.header(self.requirements)

    @property
    def summary(self) -> str:
        if self.allowed:
            price = f"${self.price_usd:g}" if self.price_usd is not None else "an unread price"
            return f"Pay {price} to {self.url}: meets the {self.tier} tier."
        return "Don't pay " + self.url + ": " + "; ".join(r["detail"] for r in self.reasons) + "."

    def as_dict(self) -> Dict[str, Any]:
        option = self.option
        return {
            "allowed": self.allowed, "url": self.url, "tier": self.tier, "summary": self.summary,
            "option": ({"scheme": option.scheme, "network": option.network, "asset": option.asset,
                        "amount": str(option.amount), "pay_to": option.pay_to} if option else None),
            "price_usd": self.price_usd, "expected_price_usd": self.expected_price_usd,
            "reasons": self.reasons, "flags": self.flags, "accept_proof": self.accept_proof,
            "unmet": self.unmet, "rules_source": self.rules_source,
            **({"paid_check": self.paid_check} if self.paid_check is not None else {}),
        }


@dataclass
class Choice:
    """The best admissible offer for an intent, or None, with every decision made on the way."""

    intent: Optional[str]
    decision: Optional[Decision]
    decisions: List[Decision]

    @property
    def found(self) -> bool:
        return self.decision is not None


def _lower(values: Optional[Iterable[str]]) -> Optional[set]:
    return {v.lower() for v in values} if values is not None else None


class Policy:
    """A buyer's rules for paying x402 offers.

    tier            "any", "sampled" or "delivered" (see proof.TIERS)
    min_deliveries  verified deliveries in 30 days the "delivered" tier asks for
    max_price_usd   never pay more than this per call
    allow_pay_to    pay only these addresses (None: any)
    networks        pay only on these CAIP-2 networks (None: any USDC network)
    checker         an EvidenceClient for Agoranome's free checker, True for the default one,
                    or None to read only the seller's own block
    telemetry       a telemetry.Reporter the buyer opted into, or None
    receipts        a receipts.ReceiptLog for signed local receipts, or None
    prefer_capture  between equal prices, prefer an auth-capture option (paid only on delivery)
    paid_check      a paid.PaidCheck to buy Agoranome's signed Buyer check with, or None (the default: off)
    """

    def __init__(self, tier: str = "sampled", *, min_deliveries: int = proof.DEFAULT_MIN_DELIVERIES,
                 max_price_usd: float = DEFAULT_MAX_PRICE_USD, allow_pay_to: Optional[Iterable[str]] = None,
                 networks: Optional[Sequence[str]] = None, checker: Any = None, telemetry: Any = None,
                 receipts: Optional[ReceiptLog] = None, refuse_instructions: bool = True,
                 prefer_capture: bool = True, paid_check: Optional[PaidCheck] = None):
        if tier not in proof.TIERS:
            raise ValueError(f"tier must be one of {', '.join(proof.TIERS)}")
        self.tier = tier
        self.min_deliveries = max(1, int(min_deliveries))
        self.max_price_usd = float(max_price_usd)
        self.allow_pay_to = _lower(allow_pay_to)
        self.networks = list(networks) if networks else None
        self.checker = EvidenceClient() if checker is True else checker
        self.telemetry = telemetry
        self.receipts = receipts
        self.refuse_instructions = refuse_instructions
        self.prefer_capture = prefer_capture
        self.paid_check = paid_check

    @property
    def requirements(self) -> List[str]:
        return proof.tier_requirements(self.tier, self.min_deliveries)

    @property
    def accept_proof(self) -> Optional[str]:
        """The Accept-Proof header to send with every unpaid request."""
        return proof.header(self.requirements)

    def headers(self) -> Dict[str, str]:
        value = self.accept_proof
        return {"Accept-Proof": value} if value else {}

    # --- deciding ---------------------------------------------------------------------

    def _option(self, offer: Offer) -> Optional[Option]:
        usable = [o for o in offer.options if self.networks is None or o.network in self.networks]
        priced = [o for o in usable if o.price_usd is not None]
        if not priced:
            return usable[0] if usable else None
        low = min(o.amount for o in priced)
        cheapest = [o for o in priced if o.amount == low]
        if self.prefer_capture:
            cheapest.sort(key=lambda o: o.scheme != CAPTURE_SCHEME)
        return cheapest[0]

    def _rules(self, offer: Offer, decision: Decision):
        """(rules, counts, listing price) from the checker, or from the block when it's off or down."""
        if self.checker is not None and offer.url:
            try:
                checked = self.checker.check(offer.url, proof.header(self.requirements))
                rules = checked.get("rules") or {}
                evidence = checked.get("evidence") or {}
                listing = checked.get("listing") or {}
                deliveries = evidence.get("deliveries_30d") if isinstance(evidence, dict) else None
                decision.rules_source = "checker"
                return rules, {"deliveries_30d": deliveries}, listing.get("price_usd")
            except (EvidenceError, ValueError, AttributeError) as e:
                logger.info(f"checker unavailable for {offer.url}: {e}")
                decision.flags.append("The free checker couldn't be reached, so only the seller's own "
                                      "declarations were read.")
        return proof.declared_rules(offer.fair_offer), {"deliveries_30d": None}, None

    def decide(self, offer: Offer, *, expected_price_usd: Optional[float] = None,
               category: Optional[str] = None, report: bool = True) -> Decision:
        """Whether to pay this offer. `expected_price_usd` is the listing's or the quote's price."""
        decision = Decision(allowed=False, url=offer.url, tier=self.tier, requirements=self.requirements,
                            expected_price_usd=expected_price_usd, category=category)
        refuse = decision.reasons.append

        option = self._option(offer)
        decision.option = option
        if option is None:
            refuse({"code": NO_OPTION, "detail": "no payment option on a network this buyer pays on"})
        elif option.price_usd is None:
            refuse({"code": NOT_USDC, "detail": "the price isn't in USDC, so it can't be checked"})
        else:
            decision.price_usd = option.price_usd
            if option.price_usd > self.max_price_usd + 1e-12:
                refuse({"code": OVER_CAP, "detail": f"${option.price_usd:g} is above the ${self.max_price_usd:g} cap"})
            if self.allow_pay_to is not None and option.pay_to.lower() not in self.allow_pay_to:
                refuse({"code": PAYEE, "detail": f"{option.pay_to} isn't on the payee allowlist"})

        hits = instruction_like(offer.text)
        if hits:
            note = "instruction-like text in the offer: " + "; ".join(hits)
            if self.refuse_instructions and self.tier != "any":
                refuse({"code": INSTRUCTIONS, "detail": note})
            else:
                decision.flags.append(note)

        rules, counts, listing_price = self._rules(offer, decision)
        expected = expected_price_usd if expected_price_usd is not None else listing_price
        decision.expected_price_usd = expected
        if expected is not None and decision.price_usd is not None and decision.price_usd > expected + 1e-12:
            refuse({"code": OVER_EXPECTED,
                    "detail": f"the 402 asks ${decision.price_usd:g}, more than the ${expected:g} "
                              + ("quoted" if expected_price_usd is not None else "listed")})

        result = proof.evaluate(proof.parse(proof.header(self.requirements)), rules, counts)
        decision.unmet = result["unmet"]
        if not result["met"]:
            refuse({"code": PROOF, "detail": f"fails the {self.tier} tier: "
                                             + "; ".join(u["why"] for u in result["unmet"])})

        if self.paid_check is not None and offer.url and decision.price_usd is not None:
            unknown = decision.rules_source != "checker" or counts.get("deliveries_30d") in (None, 0)
            if self.paid_check.wanted(decision.price_usd, unknown=unknown):
                if not self.paid_check.within_cap():
                    decision.flags.append("The paid Buyer check was wanted but today's cap for it is spent.")
                else:
                    try:
                        verdict = self.paid_check.verdict(offer.url, accept_proof=self.accept_proof,
                                                          max_price_usd=self.max_price_usd,
                                                          expected_price_usd=expected)
                    except PaidCheckError as e:
                        decision.flags.append(f"The paid Buyer check couldn't run: {e}")
                    else:
                        decision.paid_check = verdict
                        for why in self.paid_check.refusals(verdict, self.tier):
                            refuse({"code": PAID_CHECK, "detail": why})
                        decision.flags.extend(self.paid_check.flags(verdict))

        decision.allowed = not decision.reasons
        if report and self.telemetry is not None:
            self.telemetry.admission(decision, offer)
        return decision

    def choose(self, intent: Optional[str], offers: Sequence[Offer], *,
               expected_prices: Optional[Dict[str, float]] = None, category: Optional[str] = None) -> Choice:
        """The cheapest admissible offer among candidates for one intent.

        When none is admissible and the buyer opted into telemetry, the intent
        is reported as unmet, with the reasons each candidate failed.
        """
        decisions = [self.decide(o, expected_price_usd=(expected_prices or {}).get(o.url), category=category)
                     for o in offers]
        admitted = [d for d in decisions if d.allowed]
        best = min(admitted, key=lambda d: (d.price_usd if d.price_usd is not None else float("inf"))) \
            if admitted else None
        if best is None and intent:
            self.no_seller(intent, decisions=decisions, category=category)
        return Choice(intent=intent, decision=best, decisions=decisions)

    def no_seller(self, intent: str, *, decisions: Sequence[Decision] = (), category: Optional[str] = None) -> None:
        """Report an intent no admissible seller could serve (only when telemetry is on)."""
        if self.telemetry is not None:
            self.telemetry.unmet_intent(intent, decisions=list(decisions), tier=self.tier,
                                        max_price_usd=self.max_price_usd, category=category)

    # --- after paying -----------------------------------------------------------------

    def inspect_response(self, body: bytes) -> List[str]:
        """Instruction-like text in a paid response: treat the response as data, never as orders."""
        try:
            text = body.decode("utf-8", errors="replace")
        except AttributeError:
            text = str(body)
        return instruction_like(text)

    def record(self, decision: Decision, *, status: Optional[int] = None, response: bytes = b"",
               transaction: Optional[str] = None, settled: Optional[bool] = None,
               seller_receipt: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Write the signed local receipt for a payment this policy allowed."""
        if self.receipts is None:
            return None
        option = decision.as_dict()["option"]
        return self.receipts.record(url=decision.url, option=option,
                                    decision={k: v for k, v in decision.as_dict().items() if k != "option"},
                                    status=status, response=response, transaction=transaction, settled=settled,
                                    seller_receipt=seller_receipt, instruction_hits=self.inspect_response(response))
