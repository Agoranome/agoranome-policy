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

"""Free evidence from Agoranome: checked rule statuses and verified delivery counts.

Without it the policy reads only what the seller's own block declares. With
it, each Fair Offer rule comes back checked from outside (the sample fetched,
the listing price compared, the ledger reached), and "delivered" can count
deliveries reconciled against the chain. Both lookups are free and need no key.
Agoranome sees which offer was checked, not who is buying.
"""

import json
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import quote, urlencode

from agoranome_policy import __version__

DEFAULT_BASE = "https://api.agoranome.com"
CHECK_PATH = "/v1/fair-offer/check"
EVIDENCE_PATH = "/v1/evidence/"

Getter = Callable[[str], Tuple[int, bytes]]


class EvidenceError(Exception):
    pass


def urllib_get(timeout: float) -> Getter:
    def get(url: str) -> Tuple[int, bytes]:
        request = urllib.request.Request(url, headers={"User-Agent": f"agoranome-policy/{__version__}",
                                                       "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:   # noqa: S310 (https base)
                return response.status, response.read(1_000_000)
        except urllib.error.HTTPError as e:
            return e.code, e.read(10_000)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise EvidenceError(f"{url} couldn't be reached: {e}") from e
    return get


class EvidenceClient:
    def __init__(self, base_url: str = DEFAULT_BASE, *, timeout: float = 20.0, get: Optional[Getter] = None,
                 cache_seconds: float = 600.0, clock: Callable[[], float] = time.monotonic):
        self.base_url = base_url.rstrip("/")
        self.get = get or urllib_get(timeout)
        self.cache_seconds = cache_seconds
        self.clock = clock
        self._cache: Dict[str, Tuple[float, Any]] = {}

    def _json(self, url: str, missing_ok: bool = False) -> Optional[Dict[str, Any]]:
        hit = self._cache.get(url)
        if hit and self.clock() - hit[0] < self.cache_seconds:
            return hit[1]
        status, body = self.get(url)
        if missing_ok and status == 404:
            data = None
        elif not 200 <= status < 300:
            raise EvidenceError(f"{url} answered {status}")
        else:
            try:
                data = json.loads(body)
            except ValueError as e:
                raise EvidenceError(f"{url} didn't answer JSON") from e
        self._cache[url] = (self.clock(), data)
        return data

    def check(self, url: str, accept_proof: Optional[str] = None) -> Dict[str, Any]:
        """Agoranome's Fair Offer check of a live offer: rule statuses, listing counts, deliveries."""
        params = {"url": url, **({"accept_proof": accept_proof} if accept_proof else {})}
        return self._json(f"{self.base_url}{CHECK_PATH}?{urlencode(params)}") or {}

    def evidence(self, host: str) -> Optional[Dict[str, Any]]:
        """Verified deliveries and repeat buyers for a host, or None if the commons has no record."""
        return self._json(f"{self.base_url}{EVIDENCE_PATH}{quote(host, safe='')}", missing_ok=True)
