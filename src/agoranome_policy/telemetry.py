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

"""Opt-in telemetry for the two public indexes. Off unless the buyer turns it on.

Two kinds of event, both anonymized before they leave the machine:

- admission: which proof the buyer's policy asked of an offer, the offer's
  category and host, and whether it was admitted (the admission index).
- unmet_intent: what the buyer tried to buy when no candidate was admissible,
  with the reasons each failed (the unmet-intent index).

Nothing identifies the buyer: no wallet, no IP kept, no URL path, no time
finer than the day. An install sends a random id so installs can be counted
and one install can't stand in for many; it is stored on the buyer's machine
and can be reset by deleting the file. Intent text is stripped of emails,
URLs, addresses and long numbers and cut to 160 characters before it is sent,
and the index publishes an intent only once two installs have reported it.

The schema below is published at agoranome.com/standard/policy-telemetry-0.1.schema.json.
"""

import atexit
import json
import logging
import os
import re
import secrets
import threading
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence
from urllib.parse import urlsplit

from agoranome_policy import __version__, proof

logger = logging.getLogger("agoranome_policy.telemetry")

SCHEMA_ID = "agoranome-policy-telemetry/0.1"
DEFAULT_ENDPOINT = "https://api.agoranome.com/v1/policy/telemetry"
ENV_CONSENT = "AGORANOME_POLICY_TELEMETRY"
MAX_EVENTS = 100
MAX_INTENT = 160
FLUSH_AT = 20
PRICE_BUCKETS = ("<=0.001", "<=0.01", "<=0.1", "<=1", ">1")
CATEGORY = r"^[a-z0-9_]{1,40}$"
HOST = r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$"
REQUIREMENT = r"^[a-z][a-z0-9_]*(=|>=|<=)[a-z0-9_:.]+$"

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")
_URL = re.compile(r"\b(?:https?://|www\.)\S+", re.IGNORECASE)
_HEX = re.compile(r"\b0x[0-9a-fA-F]{8,}\b")
_DIGITS = re.compile(r"\d{5,}")
_SPACE = re.compile(r"\s+")

SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://agoranome.com/standard/policy-telemetry-0.1.schema.json",
    "title": "Agoranome buyer policy telemetry 0.1",
    "description": "An opt-in batch of anonymized events from a buyer's policy pack: the proof it asked of "
                   "offers (admission) and intents no admissible seller served (unmet_intent).",
    "type": "object",
    "required": ["schema", "install", "events"],
    "additionalProperties": False,
    "properties": {
        "schema": {"const": SCHEMA_ID},
        "install": {"type": "string", "pattern": "^[0-9a-f]{32}$",
                    "description": "Random id stored on the buyer's machine; counts installs, names no one."},
        "pack": {"type": "string", "maxLength": 40, "description": "Policy pack name and version."},
        "events": {"type": "array", "minItems": 1, "maxItems": MAX_EVENTS, "items": {"oneOf": [
            {"type": "object", "additionalProperties": False,
             "required": ["kind", "day", "tier", "requirements", "admitted"],
             "properties": {
                 "kind": {"const": "admission"},
                 "day": {"type": "string", "format": "date"},
                 "tier": {"enum": list(proof.TIERS)},
                 "requirements": {"type": "array", "maxItems": 12,
                                  "items": {"type": "string", "pattern": REQUIREMENT}},
                 "admitted": {"type": "boolean"},
                 "unmet": {"type": "array", "maxItems": 12, "items": {"type": "string", "pattern": REQUIREMENT}},
                 "reasons": {"type": "array", "maxItems": 8, "items": {"type": "string", "pattern": CATEGORY}},
                 "category": {"type": ["string", "null"], "pattern": CATEGORY},
                 "seller_host": {"type": ["string", "null"], "pattern": HOST},
                 "rules_source": {"enum": ["checker", "declared"]},
                 "price_bucket": {"enum": [*PRICE_BUCKETS, None]},
             }},
            {"type": "object", "additionalProperties": False, "required": ["kind", "day", "intent", "tier"],
             "properties": {
                 "kind": {"const": "unmet_intent"},
                 "day": {"type": "string", "format": "date"},
                 "intent": {"type": "string", "minLength": 3, "maxLength": MAX_INTENT},
                 "tier": {"enum": list(proof.TIERS)},
                 "category": {"type": ["string", "null"], "pattern": CATEGORY},
                 "reasons": {"type": "array", "maxItems": 8, "items": {"type": "string", "pattern": CATEGORY}},
                 "offers_seen": {"type": "integer", "minimum": 0, "maximum": 1000},
                 "max_price_bucket": {"enum": [*PRICE_BUCKETS, None]},
             }},
        ]}},
    },
}


def clean_intent(text: str) -> str:
    """An intent with anything identifying taken out, at most 160 characters."""
    text = _EMAIL.sub("[email]", text or "")
    text = _URL.sub("[url]", text)
    text = _HEX.sub("[address]", text)
    text = _DIGITS.sub("[number]", text)
    return _SPACE.sub(" ", text).strip()[:MAX_INTENT]


def price_bucket(price: Optional[float]) -> Optional[str]:
    if price is None:
        return None
    for limit, name in ((0.001, "<=0.001"), (0.01, "<=0.01"), (0.1, "<=0.1"), (1.0, "<=1")):
        if price <= limit + 1e-12:
            return name
    return ">1"


def _host(url: str) -> Optional[str]:
    host = (urlsplit(url or "").hostname or "").rstrip(".").lower()
    return host if re.match(HOST, host) else None


def _category(value: Optional[str]) -> Optional[str]:
    value = (value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return value if re.match(CATEGORY, value) else None


def _requirements(values: Sequence[str]) -> List[str]:
    return [v for v in values if re.match(REQUIREMENT, v)][:12]


def _type(value: Any, expected: Any) -> bool:
    kinds = expected if isinstance(expected, list) else [expected]
    checks = {"string": lambda v: isinstance(v, str), "null": lambda v: v is None,
              "boolean": lambda v: isinstance(v, bool), "array": lambda v: isinstance(v, list),
              "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
              "object": lambda v: isinstance(v, dict)}
    return any(checks[k](value) for k in kinds)


def _check(value: Any, schema: Dict[str, Any], where: str, problems: List[str]) -> None:
    """A small validator for the subset of JSON Schema SCHEMA uses (no dependencies)."""
    if "const" in schema and value != schema["const"]:
        problems.append(f"{where} must be {schema['const']!r}")
        return
    if "enum" in schema and value not in schema["enum"]:
        problems.append(f"{where} must be one of {schema['enum']}")
        return
    if "type" in schema and not _type(value, schema["type"]):
        problems.append(f"{where} has the wrong type")
        return
    if isinstance(value, str):
        if "pattern" in schema and not re.match(schema["pattern"], value):
            problems.append(f"{where} doesn't match {schema['pattern']}")
        if len(value) > schema.get("maxLength", 10**9) or len(value) < schema.get("minLength", 0):
            problems.append(f"{where} has the wrong length")
        if schema.get("format") == "date":
            try:
                datetime.strptime(value, "%Y-%m-%d")
            except ValueError:
                problems.append(f"{where} isn't a date")
    if isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get("minimum", -10**18) or value > schema.get("maximum", 10**18):
            problems.append(f"{where} is out of range")
    if isinstance(value, list):
        if len(value) > schema.get("maxItems", 10**9) or len(value) < schema.get("minItems", 0):
            problems.append(f"{where} has the wrong number of items")
        for i, item in enumerate(value):
            if "items" in schema:
                _check(item, schema["items"], f"{where}[{i}]", problems)
    if isinstance(value, dict):
        if "oneOf" in schema:
            options = [o for o in schema["oneOf"] if o["properties"]["kind"]["const"] == value.get("kind")]
            if not options:
                problems.append(f"{where}.kind must be admission or unmet_intent")
                return
            schema = options[0]
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                problems.append(f"{where}.{key} is required")
        for key, item in value.items():
            if key not in props:
                if schema.get("additionalProperties") is False:
                    problems.append(f"{where}.{key} isn't allowed")
                continue
            _check(item, props[key], f"{where}.{key}", problems)
    elif "oneOf" in schema:
        problems.append(f"{where} must be an object")


def validate(batch: Any) -> List[str]:
    """Problems with a telemetry batch against SCHEMA, or [] when it's valid."""
    problems: List[str] = []
    _check(batch, SCHEMA, "batch", problems)
    return problems[:20]


def _install_id(path: Path) -> str:
    try:
        value = path.read_text().strip()
        if re.match(r"^[0-9a-f]{32}$", value):
            return value
    except OSError:
        pass
    value = secrets.token_hex(16)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
    except OSError:
        pass   # an id that changes each run still counts no person
    return value


def default_id_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "agoranome-policy" / "install-id"


def _post(endpoint: str, timeout: float) -> Callable[[Dict[str, Any]], None]:
    def post(batch: Dict[str, Any]) -> None:
        request = urllib.request.Request(endpoint, data=json.dumps(batch).encode(), method="POST",
                                         headers={"Content-Type": "application/json",
                                                  "User-Agent": f"agoranome-policy/{__version__}"})
        with urllib.request.urlopen(request, timeout=timeout):   # noqa: S310 (https endpoint)
            pass
    return post


class Reporter:
    """Buffers anonymized events and sends them in batches. Never raises into the buyer's code."""

    def __init__(self, *, consent: bool, endpoint: str = DEFAULT_ENDPOINT, install_id: Optional[str] = None,
                 id_path: Optional[Path] = None, send: Optional[Callable[[Dict[str, Any]], None]] = None,
                 timeout: float = 5.0, today: Callable[[], str] = lambda: datetime.now(timezone.utc).date().isoformat()):
        if not consent:
            raise ValueError("Telemetry is opt-in: pass consent=True only when the buyer has agreed.")
        self.install = install_id or _install_id(id_path or default_id_path())
        self.send = send or _post(endpoint, timeout)
        self.today = today
        self._events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        atexit.register(self.flush)

    @classmethod
    def from_env(cls, **kwargs: Any) -> Optional["Reporter"]:
        """A reporter when AGORANOME_POLICY_TELEMETRY=1 (the buyer's opt-in), else None."""
        if os.environ.get(ENV_CONSENT, "").strip().lower() not in ("1", "true", "yes", "on"):
            return None
        return cls(consent=True, **kwargs)

    def _add(self, event: Dict[str, Any]) -> None:
        with self._lock:
            self._events.append(event)
            full = len(self._events) >= FLUSH_AT
        if full:
            self.flush()

    def admission(self, decision: Any, offer: Any) -> None:
        self._add({
            "kind": "admission", "day": self.today(), "tier": decision.tier,
            "requirements": _requirements(decision.requirements), "admitted": bool(decision.allowed),
            "unmet": _requirements([u["requirement"] for u in decision.unmet]),
            "reasons": [r["code"] for r in decision.reasons][:8],
            "category": _category(decision.category), "seller_host": _host(getattr(offer, "url", "")),
            "rules_source": decision.rules_source if decision.rules_source in ("checker", "declared") else "declared",
            "price_bucket": price_bucket(decision.price_usd),
        })

    def unmet_intent(self, intent: str, *, decisions: Sequence[Any] = (), tier: str = "sampled",
                     max_price_usd: Optional[float] = None, category: Optional[str] = None) -> None:
        text = clean_intent(intent)
        if len(text) < 3:
            return
        reasons = sorted({r["code"] for d in decisions for r in d.reasons})[:8]
        self._add({"kind": "unmet_intent", "day": self.today(), "intent": text, "tier": tier,
                   "category": _category(category), "reasons": reasons, "offers_seen": min(len(decisions), 1000),
                   "max_price_bucket": price_bucket(max_price_usd)})

    def flush(self) -> int:
        """Send what's buffered. Returns how many events were sent (0 on any failure)."""
        with self._lock:
            events, self._events = self._events[:MAX_EVENTS], self._events[MAX_EVENTS:]
        if not events:
            return 0
        batch = {"schema": SCHEMA_ID, "install": self.install, "pack": f"agoranome-policy/{__version__}",
                 "events": events}
        try:
            self.send(batch)
            return len(events)
        except Exception as e:   # telemetry must never break a purchase
            logger.info(f"telemetry not sent: {e}")
            return 0
