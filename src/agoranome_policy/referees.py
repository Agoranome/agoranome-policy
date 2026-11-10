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

"""Read a Fair Referee file and check its signatures: the rules a referee of x402 sellers binds itself to.

    from agoranome_policy import referee

    found = referee("https://agoranome.com/.well-known/fair-referee.json")
    if found["signed"]:
        rules = {r["id"] for r in found["rules"]}

A referee (Agoranome, or anyone who publishes a file of the same shape) states its rules at
/.well-known/fair-referee.json: no paid placement, every qualifying seller listed, sort keys stated, methods and
coefficients published, its own offers under the same probes and grades, and so on, each with how to check it. The
file is signed with JWS (RFC 7515) over its RFC 8785 form without `signatures`, by keys at a JWKS on the same site.

`signed` is True when at least one signature checks against a key from the JWKS of the file's own site (the same
host, or one a subdomain of the other); a JWKS or a `jku` anywhere else is not read. EdDSA (Ed25519) is checked
with the standard library alone, by RFC 8032's verification. ES256K and ES256 are checked when the `cryptography`
package is installed, and otherwise reported as not checked. Nothing is sent but the two GETs.
"""

import base64
import hashlib
import json
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from agoranome_policy.evidence import urllib_get

DEFAULT_URL = "https://agoranome.com/.well-known/fair-referee.json"
JWKS_PATH = "/.well-known/jwks.json"
KIND = "agoranome.fair-referee/1"
Getter = Callable[[str], Tuple[int, bytes]]


class RefereeError(Exception):
    pass


def canonical(value: Any) -> bytes:
    """RFC 8785's form of a document that holds no floating-point number: sorted keys, no spaces, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --- Ed25519 verification (RFC 8032, section 6) ----------------------------------------------------------------------

_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(a: Tuple[int, int, int, int], b: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    x = (a[1] - a[0]) * (b[1] - b[0]) % _P
    y = (a[1] + a[0]) * (b[1] + b[0]) % _P
    c = 2 * a[3] * b[3] * _D % _P
    d = 2 * a[2] * b[2] % _P
    e, f, g, h = y - x, d - c, d + c, y + x
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s: int, point: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    out = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            out = _add(out, point)
        point = _add(point, point)
        s >>= 1
    return out


def _equal(a: Tuple[int, int, int, int], b: Tuple[int, int, int, int]) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decompress(data: bytes) -> Optional[Tuple[int, int, int, int]]:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032's Ed25519 verification, in the standard library alone."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _Q
    return _equal(_mul(s, _G), _add(r, _mul(h, a)))


def _ecdsa_verify(jwk: Dict[str, Any], message: bytes, signature: bytes) -> Optional[bool]:
    """ES256K or ES256 (r||s, SHA-256) with the `cryptography` package; None without it."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
    except ImportError:
        return None
    curve = {"secp256k1": ec.SECP256K1, "P-256": ec.SECP256R1}.get(str(jwk.get("crv")))
    if curve is None or len(signature) != 64:
        return False
    try:
        key = ec.EllipticCurvePublicNumbers(int.from_bytes(unb64url(jwk["x"]), "big"),
                                            int.from_bytes(unb64url(jwk["y"]), "big"), curve()).public_key()
        r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        key.verify(utils.encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except (KeyError, ValueError, TypeError):
        return False


def verify(jwk: Dict[str, Any], message: bytes, signature: bytes) -> Optional[bool]:
    """Whether `signature` signs `message` under `jwk`: True, False, or None when it can't be checked here."""
    alg = jwk.get("alg")
    if alg == "EdDSA" and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        try:
            return ed25519_verify(unb64url(str(jwk.get("x") or "")), message, signature)
        except ValueError:
            return False
    if alg in ("ES256K", "ES256") and jwk.get("kty") == "EC":
        return _ecdsa_verify(jwk, message, signature)
    return None


# --- Reading a referee's file ---------------------------------------------------------------------------------------

def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def same_site(a: str, b: str) -> bool:
    """The same host, or one a subdomain of the other (agoranome.com and api.agoranome.com), both over https."""
    if urlsplit(a).scheme != "https" or urlsplit(b).scheme != "https":
        return False
    x, y = _host(a), _host(b)
    return bool(x) and (x == y or x.endswith("." + y) or y.endswith("." + x))


def _json(get: Getter, url: str) -> Any:
    status, body = get(url)
    if not 200 <= status < 300:
        raise RefereeError(f"{url} answered {status}")
    try:
        return json.loads(body)
    except ValueError as e:
        raise RefereeError(f"{url} didn't answer JSON") from e


def check(doc: Dict[str, Any], url: str, keys: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Each signature on a referee file: its key, its algorithm, and whether it checks (True, False, or None)."""
    body = {k: v for k, v in doc.items() if k != "signatures"}
    payload = b64url(canonical(body))
    by_kid = {k.get("kid"): k for k in keys if isinstance(k, dict)}
    out = []
    for item in doc.get("signatures") or []:
        found: Dict[str, Any] = {"kid": None, "alg": None, "verified": False, "why": None}
        try:
            protected = str(item["protected"])
            header = json.loads(unb64url(protected))
            found.update(kid=header.get("kid"), alg=header.get("alg"))
            jku = header.get("jku")
            key = by_kid.get(header.get("kid"))
            if jku and not same_site(str(jku), url):
                found["why"] = "its key set is on another site"
            elif key is None:
                found["why"] = "no key in the site's key set has its id"
            elif key.get("alg") and key.get("alg") != header.get("alg"):
                found["why"] = "its algorithm isn't its key's"
            else:
                found["verified"] = verify(key, f"{protected}.{payload}".encode(), unb64url(str(item["signature"])))
                if found["verified"] is None:
                    found["why"] = f"{header.get('alg')} is checked only with the cryptography package installed"
                elif not found["verified"]:
                    found["why"] = "the signature doesn't match the file"
        except (KeyError, TypeError, ValueError) as e:
            found["why"] = f"unreadable ({type(e).__name__})"
        out.append(found)
    return out


def referee(url: str = DEFAULT_URL, *, get: Optional[Getter] = None, timeout: float = 20.0) -> Dict[str, Any]:
    """A referee's file, read and checked: {signed, signatures, kind, version, referee, rules, sort_keys, methods,
    own_exam, corrections, jwks, file}. Raises RefereeError when the file can't be read."""
    if urlsplit(url).scheme != "https":
        raise RefereeError("a referee's file is read over https only")
    get = get or urllib_get(timeout)
    doc = _json(get, url)
    if not isinstance(doc, dict):
        raise RefereeError(f"{url} isn't a referee's file")
    parts = urlsplit(url)
    jwks = str(doc.get("jwks") or f"https://{parts.netloc}{JWKS_PATH}")
    if not same_site(jwks, url):
        jwks = f"https://{parts.netloc}{JWKS_PATH}"
    try:
        keys = (_json(get, jwks) or {}).get("keys") or []
    except (RefereeError, AttributeError):
        keys = []
    signatures = check(doc, url, keys if isinstance(keys, list) else [])
    return {"url": url, "signed": any(s["verified"] is True for s in signatures), "signatures": signatures,
            "kind": doc.get("kind"), "version": doc.get("version"), "referee": doc.get("referee"),
            "rules": doc.get("rules") or [], "sort_keys": doc.get("sort_keys") or [],
            "methods": doc.get("methods") or [], "own_exam": doc.get("own_exam"),
            "corrections": doc.get("corrections"), "jwks": jwks, "file": doc}
