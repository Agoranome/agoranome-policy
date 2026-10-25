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

The grammar is the Fair Offer Standard 0.2's (agoranome.com/standard#handshake):

    Accept-Proof: sample=attested; settlement=seller; price<=listing; deliveries_30d>=5

Each requirement maps to one of the seven Fair Offer rules (FO-1 to FO-7).
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
COUNTS = ("payers_30d", "calls_30d", "deliveries_30d")
SUPPORTED = {
    "sample": ("any", "attested"),
    "settlement": ("seller", "rail", "capture_on:2xx"),
    "price": ("listing",),
    "receipts": ("signed",),
    "pledge": ("ledger",),
    "instructions": ("none",),
}
MAX_REQUIREMENTS = 12

# Three tiers, from least to most proof. "delivered" counts verified deliveries
# to wallets that aren't sweep bots; raw payer counts are never used, because
# sweeps that pay every seller once inflate them.
TIERS = ("any", "sampled", "delivered")
DEFAULT_MIN_DELIVERIES = 5


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


def tier_requirements(tier: str, min_deliveries: int = DEFAULT_MIN_DELIVERIES) -> List[str]:
    """The Accept-Proof requirements a tier sends."""
    if tier not in TIERS:
        raise ValueError(f"tier must be one of {', '.join(TIERS)}")
    if tier == "any":
        return []
    wanted = ["sample=any", "instructions=none"]
    if tier == "delivered":
        wanted += ["receipts=signed", f"deliveries_30d>={max(1, int(min_deliveries))}"]
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
        rules["FO-3"] = {"status": DECLARED}
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
        return _rule(rules, "FO-3")["status"] in kept, "needs signed receipts"
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
