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

"""The buyer's own receipts: one signed line per purchase, kept locally.

Each line records what was paid, to whom, the policy decision that allowed it,
a hash of what came back and any instruction-like text found in it. Lines are
signed with HMAC-SHA256 under a key that never leaves the buyer's machine, so
the log can't be edited after the fact without it showing. Nothing here is
sent anywhere.
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

VERSION = 1


def canonical(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _key(path: Path) -> bytes:
    if path.exists():
        return bytes.fromhex(path.read_text().strip())
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key.hex())
    return key


class ReceiptLog:
    """Append-only JSON lines at `path`, signed with the key at `key_path` (created on first use)."""

    def __init__(self, path: str, key_path: Optional[str] = None):
        self.path = Path(path)
        self.key_path = Path(key_path) if key_path else self.path.with_name(self.path.name + ".key")
        self._lock = threading.Lock()

    def _sign(self, body: Dict[str, Any]) -> str:
        return hmac.new(_key(self.key_path), canonical(body), hashlib.sha256).hexdigest()

    def record(self, *, url: str, option: Optional[Dict[str, Any]], decision: Optional[Dict[str, Any]],
               status: Optional[int] = None, response: bytes = b"", transaction: Optional[str] = None,
               settled: Optional[bool] = None, seller_receipt: Optional[str] = None,
               instruction_hits: Optional[list] = None, at: Optional[datetime] = None) -> Dict[str, Any]:
        body = {
            "v": VERSION,
            "at": (at or datetime.now(timezone.utc)).isoformat(),
            "url": url,
            "option": option,
            "decision": decision,
            "status": status,
            "response_sha256": hashlib.sha256(response or b"").hexdigest(),
            "transaction": transaction,
            "settled": settled,
            "seller_receipt": seller_receipt,
            "instruction_hits": instruction_hits or [],
        }
        line = {**body, "sig": self._sign(body)}
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(line, sort_keys=True) + "\n")
        return line

    def verify(self, line: Dict[str, Any]) -> bool:
        body = {k: v for k, v in line.items() if k != "sig"}
        return hmac.compare_digest(str(line.get("sig", "")), self._sign(body))

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        if not self.path.exists():
            return iter(())
        with self.path.open(encoding="utf-8") as f:
            return iter([json.loads(row) for row in f if row.strip()])
