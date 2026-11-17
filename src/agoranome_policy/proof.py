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

"""Accept-Proof: what a buyer asks for, and whether an offer's proof meets it.

The grammar is the Fair Offer Standard 0.4's (agoranome.com/standard#handshake):

    Accept-Proof: sample=attested; settlement=seller; price<=listing; deliveries_30d>=5

Each requirement maps to one of the ten Fair Offer rules (FO-1 to FO-10). 0.3 added one_offer=checked (FO-8);
0.4 added receipts=bound (FO-3), metered=ceiling (FO-9), book=open and reports=open (FO-10).
A rule's status is "verified" (checked from outside), "declared" (the seller
says so in its block), "contradicted" or "absent". Statuses come from the 402's
own block (local) or from Agoranome's free checker, which fetches the sample,
the listing and the ledger.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

VERIFIED, DECLARED, CONTRADICTED, ABSENT = "verified", "declared", "contradicted", "absent"

_TOKEN = re.compile(r"^\s*([a-z][a-z0-9_]*)\s*(=|>=|<=)\s*([a-z0-9_:.]+)\s*$", re.IGNORECASE)
COUNTS = ("payers_30d", "calls_30d", "deliveries_30d", "buyers_30d")
SUPPORTED = {
    "sample": ("any", "attested"),
    "settlement": ("seller", "rail", "capture_on:2xx"),
    "price": ("listing",),
    "receipts": ("signed", "bound"),
    "pledge": ("ledger",),
    "instructions": ("none",),
    "one_offer": ("checked",),
    "metered": ("ceiling",),
    "book": ("open",),
    "reports": ("open",),
}
DELIVERY_HASH = "sha256-jcs"   # FO-3's receipts.delivery_hash in 0.4
MAX_REQUIREMENTS = 12

# Four tiers, from least to most proof. "facts" (0.9.0, the default) asks the
# seller for no proof and refuses on facts alone: text written to steer an agent,
# a price above the listing, a pay-to the listing doesn't name. "sampled" adds a
# free sample and the data-not-instructions promise. "delivered" counts verified
# deliveries to wallets that aren't sweep bots, from at least three distinct
# buyers (0.8.0: one wallet's five calls passed before); raw payer counts are
# never used, because sweeps that pay every seller once inflate them. "any" checks
# only the cap, the allowlist and the listing, and only flags steering text.
TIERS = ("any", "facts", "sampled", "delivered")
DEFAULT_TIER = "facts"
DEFAULT_MIN_DELIVERIES = 5
DEFAULT_MIN_BUYERS = 3


@dataclass(frozen=True)
class Requirement:
    key: str
    op: str
    value: str

    def __str__(self) -> str:
        return f"{self.key}{self.op}{self.value}"


@dataclass
class Parsed:
    requirements: List[Requirement] = field(default_factory=list)
    invalid: List[str] = field(default_factory=list)


def parse(header: Optional[str]) -> Parsed:
    """Read an Accept-Proof value: requirements separated by ';' (or ',')."""
    parsed = Parsed()
    for raw in re.split(r"[;,]", (header or "")[:512]):
        if not raw.strip():
            continue
        if len(parsed.requirements) + len(parsed.invalid) >= MAX_REQUIREMENTS:
            parsed.invalid.append("(too many requirements)")
            break
        match = _TOKEN.match(raw)
        if not match:
            parsed.invalid.append(raw.strip()[:64])
            continue
        key, op, value = match.group(1).lower(), match.group(2), match.group(3).lower()
        if key in COUNTS:
            if op != ">=" or not value.isdigit():
                parsed.invalid.append(raw.strip()[:64])
                continue
        elif key == "price":
            if value != "listing" or op not in ("<=", "="):
                parsed.invalid.append(raw.strip()[:64])
                continue
            op = "<="
        elif key in SUPPORTED:
            if op != "=" or value not in SUPPORTED[key]:
                parsed.invalid.append(raw.strip()[:64])
                continue
        else:
            parsed.invalid.append(raw.strip()[:64])
            continue
        parsed.requirements.append(Requirement(key, op, value))
    return parsed


def tier_requirements(tier: str, min_deliveries: int = DEFAULT_MIN_DELIVERIES,
                      min_buyers: int = DEFAULT_MIN_BUYERS) -> List[str]:
    """The Accept-Proof requirements a tier sends. "delivered" asks for verified deliveries and for distinct
    buyers behind them, so one wallet calling five times doesn't pass."""
    if tier not in TIERS:
        raise ValueError(f"tier must be one of {', '.join(TIERS)}")
    if tier in ("any", "facts"):
        return []
    wanted = ["sample=any", "instructions=none"]
    if tier == "delivered":
        wanted += ["receipts=signed", f"deliveries_30d>={max(1, int(min_deliveries))}",
                   f"buyers_30d>={max(1, int(min_buyers))}"]
    return wanted


def header(requirements: List[str]) -> Optional[str]:
    return "; ".join(requirements) if requirements else None


def declared_rules(info: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Rule statuses from the 402's block alone: what the seller declares.

    Price before payment (FO-1) holds for any offer that reached the policy.
    Nothing else is verified without fetching, so every claim is "declared".
    """
    info = info if isinstance(info, dict) else {}
    rules: Dict[str, Dict[str, Any]] = {"FO-1": {"status": VERIFIED}}
    settlement = info.get("settlement") if isinstance(info.get("settlement"), dict) else {}
    if settlement.get("failed_calls") == "not_charged":
        rules["FO-2"] = {"status": DECLARED, "enforced_by": settlement.get("enforced_by")}
    receipts = info.get("receipts") if isinstance(info.get("receipts"), dict) else {}
    if receipts.get("signed") is True:
        rules["FO-3"] = {"status": DECLARED, "bound": receipts.get("delivery_hash") == DELIVERY_HASH}
    sample = info.get("sample") if isinstance(info.get("sample"), dict) else {}
    if sample.get("url"):
        rules["FO-4"] = {"status": DECLARED, "attested": False}
    if info.get("listing_price_matches_offer") is True:
        rules["FO-5"] = {"status": DECLARED}
    if info.get("data_not_instructions") is True:
        rules["FO-6"] = {"status": DECLARED}
    pledge = info.get("pledge") if isinstance(info.get("pledge"), dict) else {}
    if pledge.get("ledger"):
        rules["FO-7"] = {"status": DECLARED}
    if info.get("one_offer") is True:           # 0.3
        rules["FO-8"] = {"status": DECLARED}
    metered = info.get("metered") if isinstance(info.get("metered"), dict) else {}
    if metered.get("scheme") == "upto" and metered.get("unit"):   # 0.4
        rules["FO-9"] = {"status": DECLARED}
    book = info.get("book") if isinstance(info.get("book"), dict) else {}
    if book.get("ledger"):                      # 0.4
        rules["FO-10"] = {"status": DECLARED, "reports": bool(book.get("reports"))}
    return rules


def _rule(rules: Dict[str, Dict[str, Any]], rule_id: str) -> Dict[str, Any]:
    return rules.get(rule_id) or {"status": ABSENT}


def met(req: Requirement, rules: Dict[str, Dict[str, Any]],
        counts: Dict[str, Optional[int]]) -> Tuple[bool, str]:
    """Whether one requirement is met. Same reading as Agoranome's checker."""
    kept = (VERIFIED, DECLARED)
    if req.key == "sample":
        rule = _rule(rules, "FO-4")
        if req.value == "attested":
            return (rule["status"] == VERIFIED and bool(rule.get("attested")),
                    "needs a sample whose attestation checks out")
        return rule["status"] in kept, "needs a free sample"
    if req.key == "settlement":
        rule = _rule(rules, "FO-2")
        if req.value in ("rail", "capture_on:2xx"):
            return (rule["status"] == VERIFIED and rule.get("enforced_by") == "rail",
                    "needs the payment captured only on success (auth-capture)")
        return rule["status"] in kept, "needs failed calls not to be charged"
    if req.key == "price":
        return _rule(rules, "FO-5")["status"] == VERIFIED, "needs the live price checked against the listing"
    if req.key == "receipts":
        rule = _rule(rules, "FO-3")
        if req.value == "bound":
            return (rule["status"] in kept and bool(rule.get("bound")),
                    "needs receipts bound to a hash of what was delivered")
        return rule["status"] in kept, "needs signed receipts"
    if req.key == "metered":
        return (_rule(rules, "FO-9")["status"] in kept,
                "needs a metered offer with upto, under a ceiling the buyer signs")
    if req.key == "book":
        return _rule(rules, "FO-10")["status"] == VERIFIED, "needs a receipts ledger that answers"
    if req.key == "reports":
        rule = _rule(rules, "FO-10")
        return rule["status"] == VERIFIED and bool(rule.get("reports")), "needs a list of buyers' reports that answers"
    if req.key == "one_offer":
        return (_rule(rules, "FO-8")["status"] == VERIFIED,
                "needs the same offer read under two client profiles, with no difference confirmed")
    if req.key == "pledge":
        return _rule(rules, "FO-7")["status"] == VERIFIED, "needs a pledge with a reachable public ledger"
    if req.key == "instructions":
        return (_rule(rules, "FO-6")["status"] in kept,
                "needs a data-not-instructions declaration with no instruction-like text found")
    if req.key in COUNTS:
        have = counts.get(req.key)
        if have is None:
            return False, f"{req.key} isn't known for this offer"
        return have >= int(req.value), f"needs {req.key} of at least {req.value}; it has {have}"
    return False, "unsupported requirement"


def evaluate(parsed: Parsed, rules: Dict[str, Dict[str, Any]],
             counts: Optional[Dict[str, Optional[int]]] = None) -> Dict[str, Any]:
    counts = counts or {}
    unmet = []
    for req in parsed.requirements:
        ok, why = met(req, rules, counts)
        if not ok:
            unmet.append({"requirement": str(req), "why": why})
    unmet += [{"requirement": bad, "why": "not a requirement this version understands"} for bad in parsed.invalid]
    return {"requirements": [str(r) for r in parsed.requirements] + parsed.invalid,
            "met": not unmet, "unmet": unmet}
