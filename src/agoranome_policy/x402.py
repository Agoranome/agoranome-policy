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

"""Putting the policy in front of the x402 Python SDK's client.

    from x402 import x402Client
    from agoranome_policy import Policy
    from agoranome_policy.x402 import install

    client = install(x402Client(), Policy("sampled", checker=True))

The policy runs in the client's before-payment-creation hook, so a refused
offer is never signed. Send `policy.headers()` with each unpaid request so the
seller sees your Accept-Proof. The SDK isn't a dependency of this package;
anything with `on_before_payment_creation` works.
"""

import asyncio
import inspect
from typing import Any, Callable, Optional

from agoranome_policy.offer import Offer, from_json
from agoranome_policy.policy import Decision, Policy

ABORT_PREFIX = "agoranome_policy"


def _as_dict(model: Any) -> Any:
    if hasattr(model, "model_dump"):
        return model.model_dump(by_alias=True, exclude_none=True)
    return model


def offer_from_context(context: Any) -> Offer:
    """The selected option of a payment-creation context, as an Offer."""
    required = _as_dict(context.payment_required) or {}
    selected = _as_dict(context.selected_requirements) or {}
    data = {**required, "accepts": [selected] if selected else required.get("accepts", [])}
    resource = required.get("resource") or {}
    return from_json(data, url=str(resource.get("url") or selected.get("resource") or ""))


def _abort(decision: Decision) -> Any:
    reason = f"{ABORT_PREFIX}:{decision.reasons[0]['code']}" if decision.reasons else ABORT_PREFIX
    try:
        from x402.schemas.hooks import AbortResult
    except ImportError:   # another client: hand back the same fields
        return {"abort": True, "reason": reason, "message": decision.summary}
    return AbortResult(reason=reason, message=decision.summary)


def hook(policy: Policy, *, expected_price_usd: Optional[Callable[[str], Optional[float]]] = None,
         on_decision: Optional[Callable[[Decision], None]] = None) -> Callable[[Any], Any]:
    """A synchronous before-payment hook. `expected_price_usd(url)` gives the listing's or quote's price."""

    def before_payment(context: Any) -> Any:
        offer = offer_from_context(context)
        expected = expected_price_usd(offer.url) if expected_price_usd else None
        decision = policy.decide(offer, expected_price_usd=expected)
        if on_decision is not None:
            on_decision(decision)
        return None if decision.allowed else _abort(decision)

    return before_payment


def install(client: Any, policy: Policy, **kwargs: Any) -> Any:
    """Register the policy on an x402 client (async or sync) and return the client."""
    sync_hook = hook(policy, **kwargs)
    is_async = inspect.iscoroutinefunction(getattr(client, "create_payment_payload", None))
    if is_async:
        async def before_payment(context: Any) -> Any:   # the checker does blocking I/O
            return await asyncio.to_thread(sync_hook, context)
        client.on_before_payment_creation(before_payment)
    else:
        client.on_before_payment_creation(sync_hook)
    return client
