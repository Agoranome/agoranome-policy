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

"""Reading an x402 offer: its payment options, its resource and its extensions.

A 402 carries the offer in a base64 PAYMENT-REQUIRED header (x402 v2) or as
the JSON body (v1). Either way it becomes an Offer, plain data with no SDK
types, so the policy can run anywhere.
"""

import base64
import binascii
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlsplit

FAIR_OFFER = "fair-offer"

# USDC by CAIP-2 network. Every one has six decimals.
USDC = {
    "eip155:8453": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    "eip155:84532": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
    "eip155:1": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "eip155:137": "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
    "eip155:42161": "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
    "eip155:10": "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
}
# x402 v1 network names.
LEGACY_NETWORKS = {"base": "eip155:8453", "base-sepolia": "eip155:84532", "ethereum": "eip155:1",
                   "polygon": "eip155:137", "arbitrum": "eip155:42161", "optimism": "eip155:10"}


class OfferError(ValueError):
    pass


@dataclass(frozen=True)
class Option:
    """One way to pay: an `accepts` entry."""

    scheme: str
    network: str
    asset: str
    amount: int
    pay_to: str
    raw: Dict[str, Any] = field(default_factory=dict, compare=False)

    @property
    def is_usdc(self) -> bool:
        return USDC.get(self.network) == self.asset.lower()

    @property
    def price_usd(self) -> Optional[float]:
        return self.amount / 1_000_000 if self.is_usdc else None


@dataclass
class Offer:
    url: str
    x402_version: Optional[int]
    options: List[Option]
    resource: Dict[str, Any]
    extensions: Dict[str, Any]

    @property
    def host(self) -> str:
        return (urlsplit(self.url or self.resource.get("url") or "").hostname or "").rstrip(".").lower()

    @property
    def fair_offer(self) -> Optional[Dict[str, Any]]:
        """The Fair Offer block's info, if the 402 carries one."""
        block = self.extensions.get(FAIR_OFFER)
        if isinstance(block, dict) and isinstance(block.get("info"), dict):
            return block["info"]
        return None

    @property
    def text(self) -> str:
        """The offer's own words: description and service name."""
        return " ".join(str(self.resource.get(k) or "") for k in ("description", "serviceName", "name"))

    def cheapest(self, networks: Optional[List[str]] = None) -> Optional[Option]:
        usable = [o for o in self.options if networks is None or o.network in networks]
        priced = [o for o in usable if o.price_usd is not None]
        return min(priced, key=lambda o: o.amount) if priced else (usable[0] if usable else None)


def _option(raw: Mapping[str, Any]) -> Optional[Option]:
    amount = raw.get("amount", raw.get("maxAmountRequired"))
    network = str(raw.get("network") or "")
    try:
        value = int(str(amount))
    except (TypeError, ValueError):
        return None
    if not all(raw.get(k) for k in ("scheme", "asset", "payTo")) or not network or value < 0:
        return None
    return Option(scheme=str(raw["scheme"]), network=LEGACY_NETWORKS.get(network, network),
                  asset=str(raw["asset"]), amount=value, pay_to=str(raw["payTo"]), raw=dict(raw))


def from_json(data: Mapping[str, Any], url: str = "") -> Offer:
    """An offer from the 402's decoded JSON (v2 header or v1 body)."""
    if not isinstance(data, Mapping) or not isinstance(data.get("accepts"), list):
        raise OfferError("The 402 has no accepts list.")
    resource = data.get("resource") if isinstance(data.get("resource"), dict) else {}
    if not resource and data.get("accepts") and isinstance(data["accepts"][0], dict):
        first = data["accepts"][0]   # v1 put the resource on each option
        resource = {k: first[k] for k in ("resource", "description", "mimeType") if k in first}
        if "resource" in resource:
            resource["url"] = resource.pop("resource")
    options = [o for o in (_option(a) for a in data["accepts"] if isinstance(a, Mapping)) if o]
    extensions = data.get("extensions") if isinstance(data.get("extensions"), dict) else {}
    version = data.get("x402Version")
    return Offer(url=url or str(resource.get("url") or ""), x402_version=version if isinstance(version, int) else None,
                 options=options, resource=dict(resource), extensions=dict(extensions))


def from_header(value: str, url: str = "") -> Offer:
    try:
        data = json.loads(base64.b64decode(value.strip(), validate=False))
    except (binascii.Error, ValueError, UnicodeDecodeError) as e:
        raise OfferError(f"The PAYMENT-REQUIRED header isn't base64 JSON: {e}") from e
    return from_json(data, url)


def from_response(status: int, headers: Mapping[str, str], body: bytes, url: str = "") -> Optional[Offer]:
    """The offer in an HTTP response, or None if it isn't a 402 with one."""
    if status != 402:
        return None
    lowered = {k.lower(): v for k, v in headers.items()}
    if lowered.get("payment-required"):
        return from_header(lowered["payment-required"], url)
    try:
        data = json.loads(body or b"{}")
    except (ValueError, UnicodeDecodeError):
        return None
    if isinstance(data, dict) and isinstance(data.get("accepts"), list):
        return from_json(data, url)
    return None
