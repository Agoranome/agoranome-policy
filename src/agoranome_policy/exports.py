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

"""The same rules for runtimes that can't run Python.

- cdp_policy(): a Coinbase Developer Platform wallet policy that lets the
  wallet sign x402 "exact" payments only to allowlisted payees, only in USDC,
  and only up to the cap. Create it with the CDP SDK or API
  (policies.create_policy) and attach it to the buyer account. The policy
  engine enforces the payee and the cap even if the agent's code is wrong;
  the proof tier still needs this pack or the free checker.
- cloudflare_snippet(): a confirmation callback for Cloudflare's
  withX402Client that asks Agoranome's free checker for the listing, refuses a
  price above it, a pay-to it doesn't name and (from the facts tier up) text
  written to steer an agent, and checks the buyer's Accept-Proof, before the
  agent pays.
"""

import json
import re
from typing import Any, Dict, Iterable, List, Optional

from agoranome_policy.offer import USDC
from agoranome_policy.policy import Policy

_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
CDP_MAX_ADDRESSES = 300

# x402 "exact" on EVM signs an EIP-3009 TransferWithAuthorization against the USDC contract.
TRANSFER_WITH_AUTHORIZATION = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"}, {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"},
    ],
}


def _addresses(values: Iterable[str], what: str) -> List[str]:
    out = sorted({v.strip() for v in values if v and v.strip()}, key=str.lower)
    bad = [v for v in out if not _ADDRESS.match(v)]
    if bad:
        raise ValueError(f"{what} must be 0x addresses: {', '.join(bad[:3])}")
    if not out:
        raise ValueError(f"{what} can't be empty")
    if len(out) > CDP_MAX_ADDRESSES:
        raise ValueError(f"CDP takes at most {CDP_MAX_ADDRESSES} {what} per condition")
    return out


def cdp_policy(pay_to: Iterable[str], *, max_price_usd: float = 1.0, networks: Optional[Iterable[str]] = None,
               scope: str = "account", description: str = "x402 payees and cap") -> Dict[str, Any]:
    """A CDP policy: sign x402 exact payments only to these payees, in USDC, up to the cap."""
    if scope not in ("account", "project"):
        raise ValueError("scope must be account or project")
    tokens = [USDC[n] for n in (networks or ["eip155:8453"]) if n in USDC and n.startswith("eip155:")]   # EVM only
    if not tokens:
        raise ValueError("no USDC contract is known for those networks")
    cap = int(round(float(max_price_usd) * 1_000_000))
    return {
        "scope": scope,
        "description": description[:50],
        "rules": [{
            "action": "accept",
            "operation": "signEvmTypedData",
            "criteria": [
                {"type": "evmTypedDataVerifyingContract", "addresses": _addresses(tokens, "USDC contracts"),
                 "operator": "in"},
                {"type": "evmTypedDataField",
                 "types": {"types": TRANSFER_WITH_AUTHORIZATION, "primaryType": "TransferWithAuthorization"},
                 "conditions": [
                     {"path": "to", "addresses": _addresses(pay_to, "payees"), "operator": "in"},
                     {"path": "value", "value": str(cap), "operator": "<="},
                 ]},
            ],
        }],
    }


def cdp_policy_for(policy: Policy, **kwargs: Any) -> Dict[str, Any]:
    if not policy.allow_pay_to:
        raise ValueError("A CDP policy needs a payee allowlist (allow_pay_to).")
    return cdp_policy(policy.allow_pay_to, max_price_usd=policy.max_price_usd,
                      networks=policy.networks, **kwargs)


CLOUDFLARE_SNIPPET = """\
// Agoranome policy for Cloudflare's withX402Client: pay only offers that keep to their listing and meet your
// proof tier. The free checker reads the offer from outside (the listing compared, the sample fetched, receipts
// reconciled). It sees which offer was checked, not who is buying. If it can't be reached, don't pay.
const ACCEPT_PROOF = %(accept_proof)s;
const MAX_PRICE_USD = %(max_price)s;
const REFUSE_STEERING = %(refuse_steering)s;   // the facts tier and above refuse text written to steer an agent
const V1_NETWORKS = { base: "eip155:8453", ethereum: "eip155:1", polygon: "eip155:137", arbitrum: "eip155:42161",
                      optimism: "eip155:10", "base-sepolia": "eip155:84532" };

async function confirmPayment(paymentRequirements, url) {
  const option = paymentRequirements[0];
  const price = Number(option.maxAmountRequired ?? option.amount) / 1e6;
  if (price > MAX_PRICE_USD) return false;
  const check = new URL("https://api.agoranome.com/v1/fair-offer/check");
  check.searchParams.set("url", url);
  if (ACCEPT_PROOF) check.searchParams.set("accept_proof", ACCEPT_PROOF);
  const res = await fetch(check, { headers: { accept: "application/json" } });
  if (!res.ok) return false;                      // can't check: don't pay
  const result = await res.json();
  const listing = result.listing ?? {};
  if (typeof listing.price_usd === "number" && price > listing.price_usd + 1e-12) return false;   // above the listing
  const network = V1_NETWORKS[option.network] ?? option.network;
  const payees = listing.payees?.[network];
  const payTo = String(option.payTo ?? "");
  const same = payTo.startsWith("0x") ? payTo.toLowerCase() : payTo;
  if (Array.isArray(payees) && payees.length && !payees.includes(same)) return false;   // a pay-to the listing doesn't name
  if (REFUSE_STEERING && result.facts?.steering?.length) return false;                // text written to steer an agent
  return ACCEPT_PROOF ? result.accept_proof?.met === true : true;
}

// In your Agent:
//   this.x402 = withX402Client(this.mcp.mcp, { network, account });
//   await this.x402.callTool((reqs) => confirmPayment(reqs, toolUrl), { name, arguments });
"""


def cloudflare_snippet(policy: Policy) -> str:
    return CLOUDFLARE_SNIPPET % {"accept_proof": json.dumps(policy.accept_proof or ""),
                                 "max_price": json.dumps(policy.max_price_usd),
                                 "refuse_steering": json.dumps(policy.tier != "any" and policy.refuse_instructions)}
