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
3. Payee: on the buyer's allowlist, when there is one, and named by the listing, when the
   listing is known.
4. Instructions: no text in the offer written to steer an agent (refused in every tier but "any").
5. Proof: the buyer's tier (any, facts, sampled or delivered), read from Agoranome's free
   checker when it's on, otherwise from what the seller's own block declares.

The default tier, "facts", asks the seller for no proof and refuses on facts alone: steering
text, a price above the listing, a pay-to the listing doesn't name. The listing comes from
Agoranome's free checker; when the checker can't be reached, from its last answer for the
offer (a week at most) or from the Agoranome inspector's signed weekly sheet (sheet.py), and
the decision says which. `on_checker_down="refuse"` refuses instead when no listing could be
read at all, or when a sampled or delivered tier would rest on the seller's own declarations.

An optional sixth, off unless the operator turns it on (see paid.py): buy
Agoranome's signed Buyer check ($0.01) when the seller is unknown or the price is
above a threshold, and refuse when it says the tier is not met.

Expected-loss mode (expected_loss.py), also opt-in, decides by value of
information instead of a fixed tier: the category's base rate of loss, updated
with the seller's evidence, times the price; pay when that is no more than a
check costs, check first when it's more, refuse when loss is likely.

Raw payer counts are never used. Sweep bots pay every seller once, so a high
payer count says nothing about delivery; "delivered" counts verified
deliveries to wallets that aren't sweeps, from the evidence commons.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from agoranome_policy import proof
from agoranome_policy.evidence import EvidenceClient, EvidenceError
from agoranome_policy.expected_loss import CHECK_FIRST as LOSS_CHECK_FIRST
from agoranome_policy.expected_loss import REFUSE as LOSS_REFUSE
from agoranome_policy.expected_loss import ExpectedLoss, evidence_from_rules
from agoranome_policy.instructions import instruction_like
from agoranome_policy.offer import Offer, Option
from agoranome_policy.paid import PaidCheck, PaidCheckError
from agoranome_policy.receipts import ReceiptLog
from agoranome_policy.sheet import InspectorSheet, SheetError

logger = logging.getLogger("agoranome_policy")

DEFAULT_MAX_PRICE_USD = 1.0   # default x402 clients refuse anything above $1
CAPTURE_SCHEME = "auth-capture"

# Reason codes. Telemetry reports these, never free text.
NO_OPTION = "no_usable_option"
NOT_USDC = "price_not_readable"
OVER_CAP = "over_cap"
OVER_EXPECTED = "over_listing_or_quote"
PAYEE = "payee_not_allowed"
PAYEE_LISTING = "payee_not_listed"
CHECKER_DOWN = "checker_unreachable"
INSTRUCTIONS = "instruction_like_text"
PROOF = "proof_unmet"
PAID_CHECK = "paid_check_refused"
LOSS = "expected_loss_too_high"
CHECK_FIRST = "check_first"
REASONS = (NO_OPTION, NOT_USDC, OVER_CAP, OVER_EXPECTED, PAYEE, PAYEE_LISTING, INSTRUCTIONS, PROOF, PAID_CHECK, LOSS,
           CHECK_FIRST, CHECKER_DOWN)

# What to do when the free checker can't be reached.
FALLBACK, REFUSE, ALLOW = "fallback", "refuse", "allow"
ON_CHECKER_DOWN = (FALLBACK, REFUSE, ALLOW)


def _chance(value: Any) -> bool:
    """A probability as the free checker's delivery odds give it."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and 0.0 <= value <= 1.0


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
    listing_source: Optional[str] = None   # "checker", "cache", "sheet <id>", or None when no listing was read
    category: Optional[str] = None
    paid_check: Optional[Dict[str, Any]] = None
    loss: Optional[Dict[str, Any]] = None
    delivery_odds: Optional[Dict[str, Any]] = None   # the free checker's: p, range_95, observations
    own_odds: Optional[Dict[str, Any]] = None   # a Guard's: the buyer's own record joined with them (edge.py)

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
            "unmet": self.unmet, "rules_source": self.rules_source, "listing_source": self.listing_source,
            **({"paid_check": self.paid_check} if self.paid_check is not None else {}),
            **({"loss": self.loss} if self.loss is not None else {}),
            **({"delivery_odds": self.delivery_odds} if self.delivery_odds is not None else {}),
            **({"own_odds": self.own_odds} if self.own_odds is not None else {}),
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


def _address(value: str) -> str:
    """An address as compared: EVM hex in lower case, anything else (a Solana address) as written."""
    text = str(value or "").strip()
    return text.lower() if text.lower().startswith("0x") else text


def _age(seconds: float) -> str:
    if seconds < 3600:
        return f"{max(1, round(seconds / 60))} minutes"
    if seconds < 2 * 86_400:
        return f"{round(seconds / 3600)} hours"
    return f"{round(seconds / 86_400)} days"


def _lower(values: Optional[Iterable[str]]) -> Optional[set]:
    return {v.lower() for v in values} if values is not None else None


class Policy:
    """A buyer's rules for paying x402 offers.

    tier            "facts" (the default), "any", "sampled" or "delivered" (see proof.TIERS)
    min_deliveries  verified deliveries in 30 days the "delivered" tier asks for
    min_buyers      distinct buyers behind those deliveries the "delivered" tier asks for
    max_price_usd   never pay more than this per call
    allow_pay_to    pay only these addresses (None: any)
    networks        pay only on these CAIP-2 networks (None: any USDC network)
    checker         an EvidenceClient for Agoranome's free checker, True for the default one,
                    or None to read only the seller's own block
    on_checker_down "fallback" (the default): when the checker can't be reached, read the listing from its
                    last answer for the offer or from the inspector's signed sheet, and say so; "refuse":
                    the same, but refuse when no listing could be read or a sampled or delivered tier would
                    rest on the seller's own declarations; "allow": read only the seller's own block
    sheet           the inspector's signed sheet as the second source for a listing: an InspectorSheet,
                    True for Agoranome's, None for none, or "auto" (the default: Agoranome's when
                    checker=True)
    cache_dir       a directory for the checker's last answers and the sheet's index, kept between runs
                    (None: memory only)
    telemetry       a telemetry.Reporter the buyer opted into, or None
    receipts        a receipts.ReceiptLog for signed local receipts, or None
    prefer_capture  between equal prices, prefer an auth-capture option (paid only on delivery)
    paid_check      a paid.PaidCheck to buy Agoranome's signed Buyer check with, or None (the default: off)
    expected_loss   an expected_loss.ExpectedLoss to decide by expected loss instead of the tier's proof
                    rules (use tier "any"), or None (the default: off). "Check first" buys the paid check
                    when one is set, and refuses with code check_first when not.
    """

    def __init__(self, tier: str = proof.DEFAULT_TIER, *, min_deliveries: int = proof.DEFAULT_MIN_DELIVERIES,
                 min_buyers: int = proof.DEFAULT_MIN_BUYERS, max_price_usd: float = DEFAULT_MAX_PRICE_USD, allow_pay_to: Optional[Iterable[str]] = None,
                 networks: Optional[Sequence[str]] = None, checker: Any = None, telemetry: Any = None,
                 receipts: Optional[ReceiptLog] = None, refuse_instructions: bool = True,
                 prefer_capture: bool = True, paid_check: Optional[PaidCheck] = None,
                 expected_loss: Optional[ExpectedLoss] = None, on_checker_down: str = FALLBACK,
                 sheet: Any = "auto", cache_dir: Optional[str] = None):
        if tier not in proof.TIERS:
            raise ValueError(f"tier must be one of {', '.join(proof.TIERS)}")
        if on_checker_down not in ON_CHECKER_DOWN:
            raise ValueError(f"on_checker_down must be one of {', '.join(ON_CHECKER_DOWN)}")
        self.tier = tier
        self.min_deliveries = max(1, int(min_deliveries))
        self.min_buyers = max(1, int(min_buyers))
        self.max_price_usd = float(max_price_usd)
        self.allow_pay_to = _lower(allow_pay_to)
        self.networks = list(networks) if networks else None
        self.checker = EvidenceClient(cache_dir=cache_dir) if checker is True else checker
        if sheet == "auto":
            sheet = True if checker is True else None
        self.sheet = InspectorSheet(cache_dir=cache_dir) if sheet is True else sheet
        self.on_checker_down = on_checker_down
        self.telemetry = telemetry
        self.receipts = receipts
        self.refuse_instructions = refuse_instructions
        self.prefer_capture = prefer_capture
        self.paid_check = paid_check
        self.expected_loss = expected_loss

    @property
    def requirements(self) -> List[str]:
        return proof.tier_requirements(self.tier, self.min_deliveries, self.min_buyers)

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

    @staticmethod
    def _from_check(checked: Dict[str, Any], decision: Decision, option: Optional[Option], source: str):
        """(rules, counts, listing) from one of the checker's answers."""
        rules = checked.get("rules") or {}
        evidence = checked.get("evidence") or {}
        listing = checked.get("listing") or {}
        deliveries = evidence.get("deliveries_30d") if isinstance(evidence, dict) else None
        # Distinct buyers behind those deliveries (the evidence commons' counts), for the delivered tier.
        tally = evidence.get("counts_30d") if isinstance(evidence, dict) else None
        buyers = tally.get("buyers") if isinstance(tally, dict) and deliveries is not None else None
        odds = checked.get("delivery_odds")
        decision.delivery_odds = odds if isinstance(odds, dict) and _chance(odds.get("p")) else None
        decision.rules_source = source
        found = {"price_usd": None, "payees": None, "source": None, "label": "listed"}
        if isinstance(listing, dict):
            price = listing.get("price_usd")
            found["price_usd"] = price if isinstance(price, (int, float)) and not isinstance(price, bool) else None
            payees = listing.get("payees")   # by network, from the lab's check since 0.9.0's companion release
            if isinstance(payees, dict) and option is not None and isinstance(payees.get(option.network), list):
                found["payees"] = [_address(p) for p in payees[option.network] if isinstance(p, str)]
            if found["price_usd"] is not None or found["payees"]:
                found["source"] = source
        return rules, {"deliveries_30d": deliveries, "buyers_30d": buyers}, found

    def _sheet_listing(self, offer: Offer, option: Optional[Option], decision: Decision) -> Dict[str, Any]:
        found = {"price_usd": None, "payees": None, "source": None, "label": "listed"}
        if self.sheet is None or not offer.url:
            return found
        try:
            listing = self.sheet.listing(offer.url)
        except (SheetError, ValueError, OSError) as e:
            decision.flags.append(f"The inspector's signed sheet couldn't be read either ({e}).")
            return found
        if listing is None:
            decision.flags.append("The inspector's newest signed sheet doesn't list this offer.")
            return found
        if option is not None:
            found["price_usd"] = listing.price_usd(option.network)
            found["payees"] = listing.payees(option.network) or None
        found["source"] = f"sheet {listing.sheet_id}"
        found["label"] = f"listed on the inspector's sheet {listing.sheet_id}"
        return found

    def _rules(self, offer: Offer, decision: Decision):
        """(rules, counts, listing) from the checker; when it's down, from its last answer, the inspector's sheet
        and the seller's own block, as on_checker_down says."""
        option = decision.option
        nothing = {"price_usd": None, "payees": None, "source": None, "label": "listed"}
        if self.checker is not None and offer.url:
            header = proof.header(self.requirements)
            try:
                return self._from_check(self.checker.check(offer.url, header), decision, option, "checker")
            except (EvidenceError, ValueError, AttributeError) as e:
                logger.info(f"checker unavailable for {offer.url}: {e}")
            if self.on_checker_down == ALLOW:
                decision.flags.append("The free checker couldn't be reached, so only the seller's own "
                                      "declarations were read.")
                return proof.declared_rules(offer.fair_offer), {"deliveries_30d": None, "buyers_30d": None}, nothing
            stale = getattr(self.checker, "stale", None)
            kept = stale(offer.url, header) if callable(stale) else None
            if kept is not None:
                age, checked = kept
                decision.flags.append(f"The free checker couldn't be reached; its answer for this offer from "
                                      f"{_age(age)} ago was used.")
                return self._from_check(checked, decision, option, "cache")
            listing = self._sheet_listing(offer, option, decision)
            decision.flags.append("The free checker couldn't be reached, so the seller's own declarations were "
                                  "read" + (f" and the listing came from the inspector's {listing['source']}."
                                            if listing["source"] else "; no listing could be read to compare "
                                                                      "the price and pay-to with."))
            if self.on_checker_down == REFUSE:
                if listing["source"] is None:
                    decision.reasons.append({"code": CHECKER_DOWN, "detail": "the free checker couldn't be reached "
                                             "and no listing could be read to compare the offer with"})
                elif self.tier in ("sampled", "delivered"):
                    decision.reasons.append({"code": CHECKER_DOWN, "detail": f"the free checker couldn't be "
                                             f"reached, so the {self.tier} tier would rest on the seller's own "
                                             "declarations"})
            return proof.declared_rules(offer.fair_offer), {"deliveries_30d": None, "buyers_30d": None}, listing
        return proof.declared_rules(offer.fair_offer), {"deliveries_30d": None, "buyers_30d": None}, nothing

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

        rules, counts, listing = self._rules(offer, decision)
        decision.listing_source = listing["source"]
        listing_price = listing["price_usd"]
        expected = expected_price_usd if expected_price_usd is not None else listing_price
        decision.expected_price_usd = expected
        if expected is not None and decision.price_usd is not None and decision.price_usd > expected + 1e-12:
            refuse({"code": OVER_EXPECTED,
                    "detail": f"the 402 asks ${decision.price_usd:g}, more than the ${expected:g} "
                              + ("quoted" if expected_price_usd is not None else listing["label"])})
        if option is not None and listing["payees"] and _address(option.pay_to) not in listing["payees"]:
            refuse({"code": PAYEE_LISTING,
                    "detail": f"the 402 pays {option.pay_to}, an address the listing doesn't name on "
                              f"{option.network} (" + ", ".join(listing["payees"][:3])
                              + (" ..." if len(listing["payees"]) > 3 else "") + ")"})

        result = proof.evaluate(proof.parse(proof.header(self.requirements)), rules, counts)
        decision.unmet = result["unmet"]
        if not result["met"] and self.expected_loss is None:
            refuse({"code": PROOF, "detail": f"fails the {self.tier} tier: "
                                             + "; ".join(u["why"] for u in result["unmet"])})

        if self.expected_loss is not None and decision.price_usd is not None and not decision.reasons:
            loss = self.expected_loss.decide(decision.price_usd, category=category, host=offer.url or None,
                                             evidence=evidence_from_rules(
                                                 rules if decision.rules_source == "checker" else {},
                                                 counts.get("deliveries_30d")),
                                             delivery_odds=decision.delivery_odds)
            decision.loss = loss.as_dict()
            if loss.action == LOSS_REFUSE:
                refuse({"code": LOSS, "detail": loss.summary.removeprefix("Refuse: ").rstrip(".")})
            elif loss.action == LOSS_CHECK_FIRST:
                if self.paid_check is None:
                    refuse({"code": CHECK_FIRST, "detail": loss.summary.removeprefix("Check first: ").rstrip(".")
                            + "; buy Agoranome's signed Buyer check before paying"})
                elif not self._paid_check(offer, decision, expected, refuse, tier="sampled"):
                    refuse({"code": CHECK_FIRST, "detail": "the check this payment called for couldn't be bought"})
        elif self.paid_check is not None and offer.url and decision.price_usd is not None:
            unknown = decision.rules_source != "checker" or counts.get("deliveries_30d") in (None, 0)
            if self.paid_check.wanted(decision.price_usd, unknown=unknown):
                self._paid_check(offer, decision, expected, refuse, tier=self.tier)

        decision.allowed = not decision.reasons
        if report and self.telemetry is not None:
            self.telemetry.admission(decision, offer)
        return decision

    def _paid_check(self, offer: Offer, decision: Decision, expected: Optional[float], refuse: Any,
                    tier: str) -> bool:
        """Buy the signed Buyer check and read it at `tier`; False when it couldn't be bought."""
        if not offer.url:
            return False
        if not self.paid_check.within_cap():
            decision.flags.append("The paid Buyer check was wanted but today's cap for it is spent.")
            return False
        try:
            verdict = self.paid_check.verdict(offer.url, accept_proof=self.accept_proof,
                                              max_price_usd=self.max_price_usd, expected_price_usd=expected)
        except PaidCheckError as e:
            decision.flags.append(f"The paid Buyer check couldn't run: {e}")
            return False
        decision.paid_check = verdict
        for why in self.paid_check.refusals(verdict, tier):
            refuse({"code": PAID_CHECK, "detail": why})
        decision.flags.extend(self.paid_check.flags(verdict))
        return True

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
