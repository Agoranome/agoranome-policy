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

"""The Agoranome inspector's signed weekly sheet: the guard's second source for what a listing states.

To compare a 402 with its listing, the policy asks Agoranome's free checker for the listing. When the checker
can't be reached, the policy reads the listing here instead, so the guard has no single point of failure. Every
week the inspector (github.com/Agoranome/agoranome-inspector) asks each x402 listing with real demand for its offer
and publishes what the listing states beside what the endpoint answered, signed into an open book.

This module trusts nothing the site says about itself. It reads the book, checks every entry's place, hash and
Ed25519 signature from the first key, which is pinned below, through each hand-over to a new key; finds the newest
x402 sheet the book signed; checks the sheet file's SHA-256 against the signed entry; and keeps, for each row, the
options the listing states and the sheet's verdict.

    sheet = InspectorSheet(cache_dir="~/.cache/agoranome-policy")
    listing = sheet.listing("https://api.seller.example/v1/search")
    if listing is not None:
        listing.price_usd("eip155:8453"), listing.payees("eip155:8453"), listing.sheet_id

The sheet is about 10 MB and changes weekly, so it is read once, only when the checker fails, and with a cache
directory the compact index is kept on disk for a week. Nothing is sent but GETs of public files.
"""

import base64
import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from agoranome_policy.evidence import EvidenceError, urllib_get
from agoranome_policy.offer import LEGACY_NETWORKS, USDC
from agoranome_policy.referees import ed25519_verify, unb64url

DEFAULT_SITE = "https://inspector.agoranome.com/"
# The book's first signing key, as Agoranome publishes it at agoranome.com/inspector and in the lab's configuration
# (config/runtime.yaml, inspector.first_kid). The kid is the key's RFC 7638 thumbprint, checked below.
FIRST_KEY = {"kty": "OKP", "crv": "Ed25519", "x": "TzGPmoBd9Earp5iJAQPloeNp7xO058lCCWSk8Nb7Exg",
             "kid": "7pG2bGERXACET2iKMCbgBBKsud-c-6gA-b0aoHVkgTg"}
ZERO_HASH = "0x" + "00" * 32
MAX_BOOK_BYTES = 8_000_000
MAX_SHEET_BYTES = 64_000_000
INDEX_FORMAT = "agoranome-policy/sheet-index@1"
CACHE_SECONDS = 7 * 86_400
Getter = Callable[[str], Tuple[int, bytes]]


class SheetError(Exception):
    """The sheet couldn't be read or doesn't verify. The policy goes on without it and says so."""


def thumbprint(jwk: Dict[str, Any]) -> str:
    """RFC 7638's thumbprint of an Ed25519 key."""
    members = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}, sort_keys=True,
                         separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(members).digest()).rstrip(b"=").decode()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _entry_hash(entry: Dict[str, Any]) -> str:
    core = {k: entry[k] for k in ("seq", "prev", "time", "kind", "body")}
    return "0x" + hashlib.sha256(_canonical(core)).hexdigest()


def check_book(entries: List[Dict[str, Any]], first_key: Dict[str, Any] = FIRST_KEY) -> None:
    """Every entry's place, hash and signature, from the pinned first key through each hand-over. Raises SheetError."""
    if not entries:
        raise SheetError("the inspector's book is empty")
    if thumbprint(first_key) != first_key.get("kid"):
        raise SheetError("the pinned key's kid isn't its thumbprint")
    key = None
    prev = ZERO_HASH
    for i, entry in enumerate(entries):
        try:
            if entry.get("seq") != i or entry.get("prev") != prev:
                raise SheetError(f"entry {i} of the inspector's book is out of place")
            computed = _entry_hash(entry)
        except (KeyError, TypeError, AttributeError) as e:
            raise SheetError(f"entry {i} of the inspector's book is malformed") from e
        if entry.get("hash") != computed:
            raise SheetError(f"entry {i} of the inspector's book doesn't match its hash")
        if i == 0:
            named = (entry.get("body") or {}).get("key") or {}
            if entry.get("kind") != "key" or named.get("x") != first_key["x"]:
                raise SheetError("the inspector's book doesn't start with the pinned key")
            key = first_key
        sig = entry.get("sig") or {}
        if sig.get("kid") != key.get("kid") or sig.get("alg") != "EdDSA":
            raise SheetError(f"entry {i} of the inspector's book isn't signed by the key in force")
        try:
            good = ed25519_verify(unb64url(key["x"]), bytes.fromhex(computed[2:]), unb64url(str(sig.get("value"))))
        except (ValueError, KeyError) as e:
            raise SheetError(f"entry {i} of the inspector's book has an unreadable signature") from e
        if not good:
            raise SheetError(f"entry {i} of the inspector's book has a signature that doesn't verify")
        if i > 0 and entry.get("kind") == "key":
            new = (entry.get("body") or {}).get("key")
            if not isinstance(new, dict) or new.get("kty") != "OKP" or new.get("crv") != "Ed25519" \
                    or thumbprint(new) != new.get("kid"):
                raise SheetError(f"entry {i} of the inspector's book hands over to an unusable key")
            key = new
        prev = computed


def _network(value: Any) -> str:
    text = str(value or "")
    return LEGACY_NETWORKS.get(text.lower(), text)


@dataclass
class Listing:
    """What one listing states on the inspector's newest x402 sheet."""

    resource: str
    sheet_id: str
    options: List[Dict[str, str]]          # network, asset, amount, pay_to, scheme
    matches_listing: Optional[bool]

    def price_usd(self, network: str) -> Optional[float]:
        """The lowest USDC price the listing states on `network`, or None when it states none there."""
        prices = [int(o["amount"]) / 1_000_000 for o in self.options
                  if o.get("network") == network and USDC.get(network) == str(o.get("asset") or "").lower()
                  and str(o.get("amount") or "").isdigit()]
        return min(prices) if prices else None

    def payees(self, network: str) -> List[str]:
        """The pay-to addresses the listing names on `network` (EVM addresses in lower case)."""
        out = set()
        for o in self.options:
            if o.get("network") == network and o.get("pay_to"):
                address = str(o["pay_to"])
                out.add(address.lower() if address.lower().startswith("0x") else address)
        return sorted(out)


class InspectorSheet:
    """The newest signed x402 sheet, read once when first needed.

    site       the inspector's published site (an https URL)
    cache_dir  a directory to keep the compact index in for a week (None: memory only)
    get        a callable (url) -> (status, body), for tests or another HTTP client
    first_key  the book's first key (default: Agoranome's, pinned here)
    """

    def __init__(self, site: str = DEFAULT_SITE, *, cache_dir: Optional[str] = None, timeout: float = 30.0,
                 get: Optional[Getter] = None, first_key: Dict[str, Any] = FIRST_KEY,
                 clock: Callable[[], float] = time.time, cache_seconds: float = CACHE_SECONDS):
        self.site = site.rstrip("/") + "/"
        self.cache_dir = Path(os.path.expanduser(cache_dir)) if cache_dir else None
        self.get = get or urllib_get(timeout)
        self.first_key = first_key
        self.clock = clock
        self.cache_seconds = cache_seconds
        self._index: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None

    # --- reading ---------------------------------------------------------------------

    def _fetch(self, rel: str, limit: int) -> bytes:
        try:
            status, body = self.get(self.site + rel)
        except EvidenceError as e:
            raise SheetError(str(e)) from e
        if not 200 <= status < 300:
            raise SheetError(f"{self.site + rel} answered {status}")
        if len(body) > limit:
            raise SheetError(f"{self.site + rel} is larger than {limit} bytes")
        return body

    def _build(self) -> Dict[str, Any]:
        text = self._fetch("book.jsonl", MAX_BOOK_BYTES).decode("utf-8")
        try:
            entries = [json.loads(line) for line in text.splitlines() if line.strip()]
        except ValueError as e:
            raise SheetError("the inspector's book isn't JSON lines") from e
        check_book(entries, self.first_key)
        sheets = [e for e in entries if e.get("kind") == "sheet"
                  and ((e.get("body") or {}).get("market") or "x402") == "x402"]
        if not sheets:
            raise SheetError("the inspector's book holds no x402 sheet")
        body = sheets[-1]["body"]
        rel = str(body.get("file") or "")
        if not rel.startswith("sheets/") or "/" in rel[len("sheets/"):] or not rel.endswith(".json"):
            raise SheetError("the inspector's book names a sheet outside its sheets folder")
        data = self._fetch(rel, MAX_SHEET_BYTES)
        if "0x" + hashlib.sha256(data).hexdigest() != body.get("sha256"):
            raise SheetError(f"{rel} isn't the file the inspector's book signed")
        try:
            sheet = json.loads(data)
        except ValueError as e:
            raise SheetError(f"{rel} isn't JSON") from e
        rows: Dict[str, Any] = {}
        for row in sheet.get("rows") or []:
            if not isinstance(row, dict) or not row.get("resource"):
                continue
            listed = [{"network": _network(o.get("network")), "asset": str(o.get("asset") or ""),
                       "amount": str(o.get("amount") or ""), "pay_to": str(o.get("pay_to") or ""),
                       "scheme": str(o.get("scheme") or "")}
                      for o in row.get("listed") or [] if isinstance(o, dict)]
            rows[str(row["resource"])] = {"listed": listed,
                                          "matches_listing": (row.get("verdict") or {}).get("matches_listing")}
        return {"format": INDEX_FORMAT, "site": self.site, "sheet_id": str(body.get("id") or ""),
                "rule": body.get("rule"), "read_at": self.clock(), "rows": rows}

    def _cache_path(self) -> Optional[Path]:
        if self.cache_dir is None:
            return None
        name = hashlib.sha256(self.site.encode()).hexdigest()[:16]
        return self.cache_dir / f"inspector-sheet-{name}.json"

    def _from_disk(self) -> Optional[Dict[str, Any]]:
        path = self._cache_path()
        if path is None:
            return None
        try:
            index = json.loads(path.read_text())
        except (OSError, ValueError):
            return None
        if not isinstance(index, dict) or index.get("format") != INDEX_FORMAT or index.get("site") != self.site:
            return None
        if self.clock() - float(index.get("read_at") or 0) > self.cache_seconds:
            return None
        return index

    def _to_disk(self, index: Dict[str, Any]) -> None:
        path = self._cache_path()
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handle, temporary = tempfile.mkstemp(prefix=".sheet-", dir=str(path.parent))
            with os.fdopen(handle, "w") as out:
                json.dump(index, out, separators=(",", ":"))
            os.replace(temporary, path)
        except OSError:
            pass   # the index still serves from memory

    def index(self) -> Dict[str, Any]:
        """The compact index of the newest sheet. Raises SheetError when it can't be read or doesn't verify."""
        if self._index is None:
            self._index = self._from_disk()
        if self._index is None:
            self._index = self._build()
            self._to_disk(self._index)
        return self._index

    def listing(self, resource: str) -> Optional[Listing]:
        """The listing for one resource URL on the newest sheet, or None when the sheet doesn't hold it.
        Raises SheetError when the sheet can't be read or doesn't verify."""
        index = self.index()
        row = index["rows"].get(resource) or index["rows"].get(resource.rstrip("/"))
        if row is None:
            return None
        return Listing(resource=resource, sheet_id=index["sheet_id"], options=row["listed"],
                       matches_listing=row.get("matches_listing"))
