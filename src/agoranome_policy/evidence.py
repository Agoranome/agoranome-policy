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

import hashlib
import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import quote, urlencode

from agoranome_policy import __version__

DEFAULT_BASE = "https://api.agoranome.com"
CHECK_PATH = "/v1/fair-offer/check"
EVIDENCE_PATH = "/v1/evidence/"

Getter = Callable[[str], Tuple[int, bytes]]
MAX_ANSWER_BYTES = 1_000_000   # a check, an evidence record, a feed: none comes near this
CHUNK_BYTES = 1 << 20


class EvidenceError(Exception):
    pass


def _read(response: Any, limit: int) -> bytes:
    """At most `limit` bytes of a response body, read in chunks so a large limit allocates only what arrives."""
    parts, size = [], 0
    while size < limit:
        chunk = response.read(min(CHUNK_BYTES, limit - size))
        if not chunk:
            break
        parts.append(chunk)
        size += len(chunk)
    return b"".join(parts)


def urllib_get(timeout: float, limit: int = MAX_ANSWER_BYTES) -> Getter:
    """A GET that returns (status, body), reading at most `limit` bytes of the body. A caller that must tell a
    whole file from a cut one asks for one byte more than it accepts, and refuses a body that long."""
    def get(url: str) -> Tuple[int, bytes]:
        request = urllib.request.Request(url, headers={"User-Agent": f"agoranome-policy/{__version__}",
                                                       "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:   # noqa: S310 (https base)
                return response.status, _read(response, limit)
        except urllib.error.HTTPError as e:
            return e.code, e.read(10_000)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise EvidenceError(f"{url} couldn't be reached: {e}") from e
    return get


STALE_SECONDS = 7 * 86_400   # a check answer older than a week isn't used even when the checker is down


class EvidenceClient:
    """Agoranome's free checker.

    cache_seconds  how long an answer is reused before asking again (10 minutes)
    stale_seconds  how long the last good answer for an offer is kept for when the checker can't be reached
                   (a week); `stale()` returns it, and the policy says when it used one
    cache_dir      a directory to keep those last good answers in between runs (None: memory only), so a
                   short-lived process such as the Claude Code hook has one too
    """

    def __init__(self, base_url: str = DEFAULT_BASE, *, timeout: float = 20.0, get: Optional[Getter] = None,
                 cache_seconds: float = 600.0, clock: Callable[[], float] = time.monotonic,
                 stale_seconds: float = STALE_SECONDS, cache_dir: Optional[str] = None,
                 wall: Callable[[], float] = time.time):
        self.base_url = base_url.rstrip("/")
        self.get = get or urllib_get(timeout)
        self.cache_seconds = cache_seconds
        self.clock = clock
        self.stale_seconds = stale_seconds
        self.cache_dir = Path(os.path.expanduser(cache_dir)) if cache_dir else None
        self.wall = wall
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._good: Dict[str, Tuple[float, Any]] = {}

    def _path(self, url: str) -> Optional[Path]:
        if self.cache_dir is None:
            return None
        return self.cache_dir / "checks" / (hashlib.sha256(url.encode()).hexdigest()[:32] + ".json")

    def _keep(self, url: str, data: Any) -> None:
        """The last good answer for a URL, kept for stale()."""
        now = self.wall()
        self._good[url] = (now, data)
        path = self._path(url)
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handle, temporary = tempfile.mkstemp(prefix=".check-", dir=str(path.parent))
            with os.fdopen(handle, "w") as out:
                json.dump({"url": url, "at": now, "data": data}, out)
            os.replace(temporary, path)
        except (OSError, TypeError, ValueError):
            pass   # memory still holds it

    def stale(self, url: str, accept_proof: Optional[str] = None) -> Optional[Tuple[float, Dict[str, Any]]]:
        """The last good check answer for an offer, and its age in seconds, when one is younger than
        stale_seconds; None otherwise. For use when the checker can't be reached."""
        key = self._check_url(url, accept_proof)
        found = self._good.get(key)
        if found is None:
            path = self._path(key)
            try:
                kept = json.loads(path.read_text()) if path is not None else None
            except (OSError, ValueError):
                kept = None
            if isinstance(kept, dict) and kept.get("url") == key and isinstance(kept.get("data"), dict):
                found = (float(kept.get("at") or 0), kept["data"])
        if found is None:
            return None
        age = max(0.0, self.wall() - found[0])
        return (age, found[1]) if age <= self.stale_seconds else None

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
            if isinstance(data, dict):
                self._keep(url, data)
        self._cache[url] = (self.clock(), data)
        return data

    def _check_url(self, url: str, accept_proof: Optional[str] = None) -> str:
        params = {"url": url, **({"accept_proof": accept_proof} if accept_proof else {})}
        return f"{self.base_url}{CHECK_PATH}?{urlencode(params)}"

    def check(self, url: str, accept_proof: Optional[str] = None) -> Dict[str, Any]:
        """Agoranome's Fair Offer check of a live offer: rule statuses, listing counts, deliveries."""
        return self._json(self._check_url(url, accept_proof)) or {}

    def evidence(self, host: str) -> Optional[Dict[str, Any]]:
        """Verified deliveries and repeat buyers for a host, or None if the commons has no record."""
        return self._json(f"{self.base_url}{EVIDENCE_PATH}{quote(host, safe='')}", missing_ok=True)
