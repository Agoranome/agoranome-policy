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

"""Claim labels: each claim an offer's text makes, tagged by kind and status, so a buyer's model reads the label
beside the words. Nothing is stripped.

    from agoranome_policy import annotate

    for claim in annotate(offer):            # an Offer, the 402's JSON, or the text itself
        print(claim["kind"], claim["status"], claim["text"])

Kinds: count (a number with a noun such as payers, calls, users, uptime), standing (best, number one, official,
fastest), endorsement (used by, trusted by, partner of), urgency (limited time, act now), authority (certified,
audited, compliant), pledge (donates, a share of revenue) and instruction (text written to steer an agent).

Statuses: verified (the Bazaar's own 30-day count agrees within 10%, or a record you pass in does), unverified,
contradicted (a payer or call count over the same 30 days that the Bazaar's own count is more than 10% below), and
steering (urgency and instructions). An honest seller's true but unprovable claim reads "unverified", never
"false". The counts come from Agoranome's free checker when the Policy reads it (Decision.claims), or from
`counts=` here; `evidence=` takes what you hold on the host (certification: "certified" or "failed";
admission_tier; pledge_verification: {"status", "checked_at"}). The same rules label claims in Agoranome's signed
Buyer check.
"""

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from agoranome_policy.instructions import instruction_like
from agoranome_policy.offer import Offer, from_json

# Claims of standing, by the label a report shows for each.
STANDING_PATTERNS = {
    "best": r"\bbest\b", "#1": r"#\s?1\b", "number one": r"\bnumber one\b",
    "top-rated": r"\btop[- ]rated\b", "award-winning": r"\baward[- ]winning\b",
    "official": r"\bofficial\b", "certified": r"\bcertified\b", "verified": r"\bverified\b",
    "guaranteed": r"\bguarantee[sd]?\b", "recommended": r"\brecommended\b",
    "trusted by": r"\btrusted by\b", "leading": r"\b(industry[- ])?leading\b",
    "fastest": r"\bfastest\b", "cheapest": r"\bcheapest\b", "lowest": r"\blowest\b",
    "most ...": r"\bmost (popular|trusted|reliable|accurate|used)\b",
    "unmatched": r"\bunmatched\b", "unbeatable": r"\bunbeatable\b", "perfect": r"\bperfect\b",
    "100%": r"\b100\s?%",
}

KINDS = ("count", "standing", "endorsement", "urgency", "authority", "pledge", "instruction")
VERIFIED, UNVERIFIED, CONTRADICTED, STEERING = "verified", "unverified", "contradicted", "steering"
STATUSES = (VERIFIED, UNVERIFIED, CONTRADICTED, STEERING)
COUNT_TOLERANCE = 0.10   # a count within 10% of the Bazaar's own is verified
MAX_CLAIMS = 20
_SNIPPET = 120

_MAGNITUDE = r"(?:k|m|b|thousand|million|billion)"
_AMOUNT = rf"\d[\d,]*(?:\.\d+)?\s?{_MAGNITUDE}?\b\+?"
_PAYER_WORDS = r"payers?|paying (?:agents?|users?|customers?|clients?)|buyers?"
_CALL_WORDS = r"(?:api |paid )?(?:calls?|requests?|queries|transactions|settlements?|payments?)"
_OTHER_WORDS = (r"users?|customers?|clients?|agents?|developers?|devs|teams?|companies|businesses|enterprises|"
                r"installs?|downloads?|integrations?|uptime|countries|endpoints|sources")
_COUNT_RE = re.compile(
    rf"(?P<bound>\b(?:over|more than|at least|above|upwards of)\s+)?(?P<amount>{_AMOUNT})\s*(?:%\s*)?"
    rf"(?:\w+\s+){{0,2}}?(?P<noun>{_PAYER_WORDS}|{_CALL_WORDS}|{_OTHER_WORDS})\b"
    r"(?P<period>[^.;,]{0,24}?\b(?:a|per|each|every|this|last|in the last|past)\s+(?:30 days|month|mo)\b|"
    r"\s*/\s*(?:month|mo)\b|\s+monthly\b)?",
    re.IGNORECASE)
_STANDING_KIND = {label: r for label, r in STANDING_PATTERNS.items()
                  if label not in ("certified", "verified", "trusted by")}
_STANDING_KIND["trusted"] = r"\btrusted\b(?! by)"
KIND_PATTERNS: Dict[str, Dict[str, str]] = {
    "standing": _STANDING_KIND,
    "endorsement": {
        "used by": r"\bused by\b", "trusted by": r"\btrusted by\b", "loved by": r"\bloved by\b",
        "chosen by": r"\bchosen by\b", "backed by": r"\bbacked by\b", "endorsed by": r"\bendorsed by\b",
        "partner": r"\b(?:official )?partner(?:ed)? (?:of|with)\b|\bin partnership with\b",
        "as seen in": r"\bas (?:seen|featured) (?:in|on)\b|\bfeatured (?:in|on|by)\b",
    },
    "urgency": {
        "limited": r"\blimited[- ](?:time|offer|spots?|availability|supply)\b",
        "today only": r"\btoday only\b|\bonly today\b",
        "last chance": r"\blast chance\b", "act now": r"\b(?:act|buy|call|order|sign up) now\b",
        "hurry": r"\bhurry\b", "before it's gone": r"\bbefore (?:it'?s|they'?re) gone\b",
        "only N left": r"\bonly \d+ (?:left|remaining)\b", "expires soon": r"\bexpires? soon\b",
        "don't miss": r"\bdon'?t miss\b",
    },
    "authority": {
        "certified": r"\bcertified\b", "verified": r"\bverified\b", "audited": r"\baudited\b",
        "compliant": r"\bcompliant\b|\bcompliance\b", "accredited": r"\baccredited\b",
        "licensed": r"\blicensed\b", "regulated": r"\bregulated\b",
        "SOC 2": r"\bsoc ?2\b", "ISO 27001": r"\biso ?27001\b",
    },
    "pledge": {
        "donates": r"\bdonat(?:e|es|ed|ing|ion)s?\b", "pledge": r"\bpledge[sd]?\b",
        "share of revenue": r"\b\d+(?:\.\d+)?\s?% of (?:(?:our|its|all|every|each) )?(?:revenue|profits?|proceeds|sales|fees)\b",
        "gives back": r"\bgives? back\b", "charity": r"\bcharit(?:y|ies|able)\b",
    },
}
_KIND_RES = {kind: {label: re.compile(p, re.IGNORECASE) for label, p in found.items()}
             for kind, found in KIND_PATTERNS.items()}
# A claim of Agoranome's own standard: only these can be contradicted by Agoranome's own records.
# Each kind's patterns as one, for `kinds_in`: does the text make a claim of the kind at all.
_KIND_ANY = {kind: re.compile("|".join(f"(?:{p.pattern})" for p in found.values()), re.IGNORECASE)
             for kind, found in _KIND_RES.items()}
_OURS_RE = re.compile(r"\b(?:fair offer|agoranome)\b", re.IGNORECASE)
_OTHER_STANDARD_RE = re.compile(r"\b(?:soc ?\d|iso ?\d+|hipaa|gdpr|pci|fedramp|ccpa)\b", re.IGNORECASE)


def _snippet(text: str, start: int, end: int) -> str:
    """The claim with a little of the sentence around it, never past the sentence."""
    left = max(text.rfind(stop, 0, start) for stop in (".", "!", "?", ";", "\n")) + 1
    right = [i for i in (text.find(stop, end) for stop in (".", "!", "?", ";", "\n")) if i != -1]
    right = min(right) if right else len(text)
    found = " ".join(text[left:right].split())
    if len(found) <= _SNIPPET:
        return found
    middle = " ".join(text[start:end].split())
    pad = max((_SNIPPET - len(middle)) // 2, 0)
    return " ".join(text[max(start - pad, left):min(end + pad, right)].split())


def _amount(text: str) -> Optional[float]:
    m = re.match(r"(\d[\d,]*(?:\.\d+)?)\s?(k|m|b|thousand|million|billion)?", text.strip(), re.IGNORECASE)
    if not m:
        return None
    try:
        value = float(m.group(1).replace(",", ""))
    except ValueError:
        return None
    scale = {"k": 1e3, "thousand": 1e3, "m": 1e6, "million": 1e6, "b": 1e9, "billion": 1e9}
    return value * scale.get((m.group(2) or "").lower(), 1)


def _count_status(match: "re.Match", counts: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """A payer or call count against the Bazaar's own 30-day count for the listing.

    Verified within COUNT_TOLERANCE (or, for "over N" and "N+", when the count is at least N less the tolerance).
    Contradicted only when the claim is above the count by more than the tolerance and names the same 30-day or
    monthly period the Bazaar counts; a larger number over another period (or none) may be true, so it's
    unverified."""
    noun = match.group("noun").lower()
    if "%" in match.group(0).split(match.group("noun"))[0]:
        return UNVERIFIED, None
    if re.fullmatch(_PAYER_WORDS, noun, re.IGNORECASE):
        key = "payers_30d"
    elif re.fullmatch(_CALL_WORDS, noun, re.IGNORECASE):
        key = "calls_30d"
    else:
        return UNVERIFIED, None
    count, claimed = counts.get(key), _amount(match.group("amount"))
    if not isinstance(count, (int, float)) or isinstance(count, bool) or claimed is None or count < 0:
        return UNVERIFIED, None
    source = f"the Bazaar's {key.replace('_30d', '')} in 30 days ({int(count):,})"
    lower_bound = bool(match.group("bound")) or match.group("amount").rstrip().endswith("+")
    if lower_bound and count >= claimed * (1 - COUNT_TOLERANCE):
        return VERIFIED, source
    if not lower_bound and abs(claimed - count) <= COUNT_TOLERANCE * max(count, 1):
        return VERIFIED, source
    if claimed > count * (1 + COUNT_TOLERANCE) and match.group("period"):
        return CONTRADICTED, source
    return UNVERIFIED, None


def _authority_status(snippet: str, label: str, evidence: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """"Certified" and "verified" against Agoranome's own records: verified when the host passed a Fair Offer
    certification or is in the admission feed; contradicted only when the claim names Agoranome's standard and the
    host's newest certification failed or lapsed. Never certified, or another body's standard: unverified."""
    if label not in ("certified", "verified") or _OTHER_STANDARD_RE.search(snippet):
        return UNVERIFIED, None
    certification = str(evidence.get("certification") or "")
    tier = evidence.get("admission_tier")
    if certification == "certified":
        return VERIFIED, "Agoranome's Fair Offer certification (passed)"
    if tier:
        return VERIFIED, f"Agoranome's admission feed ({tier})"
    if _OURS_RE.search(snippet) and certification in ("failed", "failing", "expired"):
        return CONTRADICTED, f"Agoranome's Fair Offer certification ({certification})"
    return UNVERIFIED, None


def _pledge_status(evidence: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    kept = evidence.get("pledge_verification") if isinstance(evidence.get("pledge_verification"), dict) else {}
    if kept.get("status") in (VERIFIED, CONTRADICTED):
        return kept["status"], f"Agoranome's pledge check of the seller's ledger ({str(kept.get('checked_at'))[:10]})"
    return UNVERIFIED, None


def claims(texts: Iterable[Optional[str]], *, counts: Optional[Dict[str, Any]] = None,
           evidence: Optional[Dict[str, Any]] = None) -> List[Dict[str, Optional[str]]]:
    """Each claim in an offer's texts, labelled: [{text, kind, status, source}], in the order the texts make them.

    ``counts`` are the Bazaar's own counts for the listing (payers_30d, calls_30d); ``evidence`` is what Agoranome
    holds on the host (certification: its status; admission_tier; pledge_verification: the daily pledge check's
    kept verdict on the host's ledger, strategy 8). A pledge claim takes that verdict's status when it is verified
    or contradicted, and stays unverified otherwise."""
    counts, evidence = counts or {}, evidence or {}
    found: List[Tuple[int, int, Dict[str, Optional[str]]]] = []
    seen = set()

    def add(order: int, at: int, text: str, kind: str, status: str, source: Optional[str]) -> None:
        key = (kind, text.lower())
        if key not in seen:
            seen.add(key)
            found.append((order, at, {"text": text, "kind": kind, "status": status, "source": source}))

    for order, text in enumerate(t for t in texts if t):
        for m in _COUNT_RE.finditer(text):
            status, source = _count_status(m, counts)
            add(order, m.start(), _snippet(text, m.start(), m.end()), "count", status, source)
        for kind, patterns in _KIND_RES.items():
            for label, pattern in patterns.items():
                for m in pattern.finditer(text):
                    snippet = _snippet(text, m.start(), m.end())
                    if kind == "urgency":
                        status, source = STEERING, None
                    elif kind == "authority":
                        status, source = _authority_status(snippet, label, evidence)
                    elif kind == "pledge":
                        status, source = _pledge_status(evidence)
                    else:
                        status, source = UNVERIFIED, None
                    add(order, m.start(), snippet, kind, status, source)
        for hit in instruction_like(text):
            at = text.lower().find(hit.lower())
            add(order, max(at, 0), _snippet(text, max(at, 0), max(at, 0) + len(hit)), "instruction", STEERING, None)
    return [c for _, _, c in sorted(found, key=lambda f: (f[0], f[1]))][:MAX_CLAIMS]


def annotate(offer: Union[Offer, Dict[str, Any], str, None], *, counts: Optional[Dict[str, Any]] = None,
             evidence: Optional[Dict[str, Any]] = None) -> List[Dict[str, Optional[str]]]:
    """Each claim in an offer's own words, labelled: [{text, kind, status, source}] in the order the text makes
    them (at most twenty). `offer`: an Offer, the 402's decoded JSON, or the text. `counts`: the Bazaar's 30-day
    payers_30d and calls_30d for the listing (the free checker's `listing`)."""
    if offer is None:
        return []
    if isinstance(offer, str):
        texts = [offer]
    else:
        if not isinstance(offer, Offer):
            offer = from_json(offer)
        texts = [str(offer.resource.get(k) or "") for k in ("description", "serviceName", "name")]
    return claims(texts, counts=counts, evidence=evidence)
