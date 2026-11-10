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

"""One call before an x402 payment: `before_pay(offer)`.

The free checks always run first: the price against your cap and against the listing or the quote, the payee,
any text in the offer written to steer an agent, and what Agoranome's free checker holds on the seller.

Agoranome's signed Buyer check ($0.01) is bought only in the tail, where a check is worth its cent:

- the first payment to a pay-to address this guard hasn't paid before;
- a price above a dime;
- an expected loss above the check's price: (1 - p) x price > $0.01, with p the seller's delivery odds from the
  free checker (a probability with a 95% range, from Agoranome's probes, reconciled deliveries, returning buyers
  and settlement proofs);
- a seller the free checker couldn't vouch for.

At the market's base rates, a routine repeat payment of a few cents to a known seller loses less in expectation
than a check costs, so it pays without one. On a first payment to an unknown pay-to the loss at stake is the whole
balance, and a check is worth more than its price.

    from agoranome_policy import Guard

    guard = Guard(pay=lambda url: paying.get(url).json())   # your x402 client performs the paid GET
    decision = guard(offer)                                  # an Offer, or the 402's JSON
    if decision.allowed:
        ...                                                  # pay decision.option

Without `pay=`, nothing is ever bought: the decision says where a check would have been worth its cent. Keep one
Guard for an agent's whole run, so its daily cap and the pay-to addresses it has paid hold across calls.
`before_pay(offer, ...)` uses one such guard per set of options. A Guard can also stand in for a Policy:
`install(client, guard)` from agoranome_policy.x402 runs it in the x402 client's before-payment hook.

To keep the pay-to addresses between runs, give the guard a file: `Guard(pay=..., memory="~/.agoranome/pay-to.json")`
(or set AGORANOME_POLICY_MEMORY to its path). A pay-to is remembered when the guard allows a payment to it, for
`memory_days` (30) after the last one, so a seller unpaid for a month is checked again. The file holds only
addresses and dates; a file that can't be read or written leaves the guard working from what it holds in memory.

To let the guard learn from your own payments, give it a receipt log and record each payment's outcome:
`Guard(pay=..., receipts="~/.agoranome/receipts.jsonl")`, then `guard.record(decision, status=200, settled=True,
response=body)`. It keeps a private Beta per pay-to from its own signed receipts and joins it with Agoranome's
delivery odds (edge.py), so after about ten calls your own experience leads; `decision.own_odds` shows the result,
and the expected-loss rule reads it. `guard.choose(offers)` picks the cheapest admissible offer and, among offers
at the same price, tries them in the order of one draw from each one's Beta. Nothing of the record leaves your
machine.
"""

import json
import os
import random
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Set, Tuple, Union

from agoranome_policy.edge import OwnRecord
from agoranome_policy.evidence import DEFAULT_BASE
from agoranome_policy.offer import Offer, from_json
from agoranome_policy.paid import PaidCheck
from agoranome_policy.policy import DEFAULT_MAX_PRICE_USD, Choice, Decision, Policy
from agoranome_policy.receipts import ReceiptLog

ABOVE_USD = 0.10          # a price from which a check is worth its cent
CHECK_USD = 0.01          # what Agoranome's signed Buyer check costs
DAILY_CAP_USD = 0.05      # at most five checks a day
MAX_GUARDS = 32
MEMORY_DAYS = 30.0        # a remembered pay-to is checked again after this many days without a payment
MEMORY_ENV = "AGORANOME_POLICY_MEMORY"
MEMORY_FORMAT = "agoranome-policy/pay-to-memory@1"
MAX_REMEMBERED = 10000    # the oldest go first past this many addresses


class Memory:
    """The pay-to addresses a guard has allowed a payment to, with the last time, kept in a JSON file.

    Reads and writes never raise: a missing, unreadable or foreign file counts as empty, and a write that fails
    leaves the guard working from memory. Writes go to a temporary file in the same folder and replace the file,
    re-reading it first, so two runs sharing one file keep each other's addresses."""

    def __init__(self, path: Union[str, "os.PathLike[str]"], days: float = MEMORY_DAYS,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.path = Path(os.path.expanduser(os.fspath(path)))
        self.days = float(days)
        self.clock = clock
        self.error: Optional[str] = None

    def _read(self) -> Dict[str, str]:
        try:
            data = json.loads(self.path.read_text())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            self.error = f"couldn't read {self.path}: {type(e).__name__}"
            return {}
        if not isinstance(data, dict) or data.get("format") != MEMORY_FORMAT or not isinstance(data.get("pay_to"), dict):
            self.error = f"{self.path} isn't a pay-to memory file; it is left as it is"
            return {}
        return {str(k).lower(): str(v) for k, v in data["pay_to"].items() if isinstance(v, str)}

    def _fresh(self, kept: Dict[str, str]) -> Dict[str, str]:
        oldest = self.clock() - timedelta(days=self.days)
        out = {}
        for address, at in kept.items():
            try:
                when = datetime.fromisoformat(at.replace("Z", "+00:00"))
            except ValueError:
                continue
            if (when if when.tzinfo else when.replace(tzinfo=timezone.utc)) >= oldest:
                out[address] = at
        return out

    def known(self) -> Set[str]:
        """The addresses paid within `days`."""
        return set(self._fresh(self._read()))

    def _write(self, kept: Dict[str, str]) -> None:
        if self.error and "isn't a pay-to memory file" in self.error:
            return   # never overwrite a file this package didn't write
        newest = dict(sorted(kept.items(), key=lambda kv: kv[1], reverse=True)[:MAX_REMEMBERED])
        body = json.dumps({"format": MEMORY_FORMAT, "pay_to": dict(sorted(newest.items()))}, indent=1)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle, temporary = tempfile.mkstemp(prefix=".pay-to-", dir=str(self.path.parent))
            try:
                with os.fdopen(handle, "w") as out:
                    out.write(body)
                os.replace(temporary, self.path)
            except BaseException:
                if os.path.exists(temporary):
                    os.unlink(temporary)
                raise
            self.error = None
        except OSError as e:
            self.error = f"couldn't write {self.path}: {type(e).__name__}"

    def remember(self, address: str) -> None:
        kept = self._fresh(self._read())
        kept[address.lower()] = self.clock().isoformat(timespec="seconds")
        self._write(kept)

    def forget(self, address: str) -> None:
        kept = self._fresh(self._read())
        if kept.pop(address.lower(), None) is not None:
            self._write(kept)


def _offer(offer: Any, url: str = "") -> Offer:
    if isinstance(offer, Offer):
        return offer
    if isinstance(offer, Mapping):
        return from_json(offer, url)
    raise TypeError("before_pay takes an Offer or the 402's decoded JSON")


class Guard:
    """The free checks on every payment, and Agoranome's signed Buyer check only where it is worth its cent.

    pay            a callable that performs the paid GET of a URL and returns its JSON body; None: never buy
    max_price_usd  never pay more than this per call
    above_usd      a price above this buys the check
    daily_cap_usd  never spend more than this on checks per UTC day
    checker        Agoranome's free checker (True: the default one; None: read only the seller's own block)
    allow_pay_to   pay only these addresses (None: any)
    networks       pay only on these CAIP-2 networks (None: any USDC network)
    known_pay_to   pay-to addresses already paid, so a first payment to them doesn't buy a check
    memory         a JSON file that keeps the pay-to addresses paid between runs (None: AGORANOME_POLICY_MEMORY,
                   or none); memory_days: how long one is remembered after its last payment
    receipts       a receipt log (a ReceiptLog or a path) to learn the buyer's own delivery record from, and to
                   write each recorded payment to (None: no record of its own)
    rng            the random source for choose()'s draws among ties (None: Python's)
    """

    tier = "any"

    def __init__(self, pay: Optional[Callable[[str], Any]] = None, *, max_price_usd: float = DEFAULT_MAX_PRICE_USD,
                 above_usd: float = ABOVE_USD, daily_cap_usd: float = DAILY_CAP_USD, checker: Any = True,
                 base_url: str = DEFAULT_BASE, allow_pay_to: Optional[Iterable[str]] = None,
                 networks: Optional[Sequence[str]] = None, known_pay_to: Iterable[str] = (),
                 memory: Optional[Union[str, "os.PathLike[str]"]] = None, memory_days: float = MEMORY_DAYS,
                 receipts: Optional[Union[ReceiptLog, str, "os.PathLike[str]"]] = None,
                 rng: Optional[random.Random] = None):
        self.free = Policy("any", max_price_usd=max_price_usd, checker=checker, allow_pay_to=allow_pay_to,
                           networks=networks)
        self.paid_check = (PaidCheck(pay, base_url=base_url, when="always", daily_cap_usd=daily_cap_usd)
                           if pay is not None else None)
        self.checked = (Policy("any", max_price_usd=max_price_usd, checker=self.free.checker,
                               allow_pay_to=allow_pay_to, networks=networks, paid_check=self.paid_check)
                        if self.paid_check is not None else None)
        self.above_usd = float(above_usd)
        self.known: Set[str] = {a.lower() for a in known_pay_to}
        path = memory if memory is not None else (os.environ.get(MEMORY_ENV) or None)
        self.memory: Optional[Memory] = Memory(path, memory_days) if path else None
        if self.memory is not None:
            self.known |= self.memory.known()
        if receipts is not None and not isinstance(receipts, ReceiptLog):
            receipts = ReceiptLog(os.path.expanduser(os.fspath(receipts)))
        self.receipts: Optional[ReceiptLog] = receipts
        self.own = OwnRecord(receipts)
        self.rng = rng

    def forget(self, pay_to: str) -> None:
        """Forget a pay-to (a payment the guard allowed that didn't go through), here and in the memory file."""
        self.known.discard(pay_to.lower())
        if self.memory is not None:
            self.memory.forget(pay_to)

    # Policy's face, so install() from agoranome_policy.x402 can run a Guard.
    @property
    def accept_proof(self) -> Optional[str]:
        return None

    def headers(self) -> Dict[str, str]:
        return {}

    def why_check(self, decision: Decision) -> Optional[str]:
        """Why this payment is in the tail where a check is worth its cent, or None."""
        pay_to = decision.option.pay_to.lower() if decision.option else ""
        if pay_to and pay_to not in self.known:
            return "a first payment to this pay-to address"
        if decision.price_usd is not None and decision.price_usd > self.above_usd + 1e-12:
            return f"a price above ${self.above_usd:g}"
        odds = (decision.own_odds or decision.delivery_odds or {}).get("p")
        if decision.price_usd is not None and isinstance(odds, (int, float)):
            loss = (1.0 - float(odds)) * decision.price_usd
            if loss > CHECK_USD + 1e-12:
                whose = " (with your own record)" if decision.own_odds is not None else ""
                return (f"an expected loss of ${loss:.4f} at delivery odds of {float(odds):.0%}{whose}, more than "
                        f"the check's ${CHECK_USD:g}")
        if decision.rules_source != "checker":
            return "a seller the free checker couldn't vouch for"
        return None

    def decide(self, offer: Any, *, expected_price_usd: Optional[float] = None, category: Optional[str] = None,
               report: bool = True) -> Decision:
        offer = _offer(offer)
        decision = self.free.decide(offer, expected_price_usd=expected_price_usd, category=category, report=False)
        self._own_odds(decision)
        if not decision.allowed:
            return decision
        why = self.why_check(decision)
        if why is not None and self.checked is not None:
            decision = self.checked.decide(offer, expected_price_usd=expected_price_usd, category=category,
                                           report=False)
            self._own_odds(decision)
            if decision.paid_check is not None:
                decision.flags.insert(0, f"Bought Agoranome's signed Buyer check: {why}.")
        elif why is not None:
            decision.flags.append(f"Agoranome's signed Buyer check ($0.01) would be worth its cent here ({why}); "
                                  "pass pay= to buy it.")
        if decision.allowed and decision.option is not None:
            self.known.add(decision.option.pay_to.lower())
            if self.memory is not None:
                self.memory.remember(decision.option.pay_to)
                if self.memory.error:
                    decision.flags.append(f"Pay-to memory not kept: {self.memory.error}.")
        return decision

    __call__ = decide

    def _own_odds(self, decision: Decision) -> None:
        if decision.option is not None:
            decision.own_odds = self.own.beta(decision.option.pay_to, decision.delivery_odds)

    def record(self, decision: Decision, *, status: Optional[int] = None, response: bytes = b"",
               transaction: Optional[str] = None, settled: Optional[bool] = None,
               seller_receipt: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """After paying: the payment's outcome, learned from (a settled 2xx at the price expected counts good) and
        written as a signed receipt when the guard has a log. Returns the receipt, or None without a log."""
        option = decision.as_dict()["option"]
        line = {"option": option, "decision": {k: v for k, v in decision.as_dict().items() if k != "option"},
                "status": status, "settled": settled}
        if self.receipts is not None:
            line = self.receipts.record(url=decision.url, option=option, decision=line["decision"], status=status,
                                        response=response, transaction=transaction, settled=settled,
                                        seller_receipt=seller_receipt,
                                        instruction_hits=self.free.inspect_response(response))
        self.own.add(line)
        return line if self.receipts is not None else None

    def choose(self, offers: Sequence[Any], *, intent: Optional[str] = None,
               expected_prices: Optional[Mapping[str, float]] = None, category: Optional[str] = None) -> Choice:
        """The cheapest offer the guard allows. The free checks run on every candidate; among the admissible ones
        at the lowest price, one draw from each one's Beta (your record joined with Agoranome's odds) orders the
        tries, and a check is bought, where one is worth its cent, only for the offer about to be paid."""
        offers = [_offer(o) for o in offers]
        expected = dict(expected_prices or {})
        free = [self.free.decide(o, expected_price_usd=expected.get(o.url), category=category, report=False)
                for o in offers]
        for d in free:
            self._own_odds(d)
        admitted = [(d, o) for d, o in zip(free, offers) if d.allowed and d.price_usd is not None]
        draws = {id(d): self.own.draw(d.option.pay_to, d.delivery_odds, self.rng) for d, _ in admitted}
        admitted.sort(key=lambda pair: (round(pair[0].price_usd, 9), -draws[id(pair[0])]))
        decisions = list(free)
        place = {id(d): i for i, d in enumerate(free)}
        for d, o in admitted:
            final = self.decide(o, expected_price_usd=expected.get(o.url), category=category)
            if final.allowed:
                final.flags.append(f"Chosen among {len(admitted)} admissible offers: the cheapest"
                                   + (", and the best of one draw from each one's odds among those at its price"
                                      if sum(abs(x.price_usd - d.price_usd) < 1e-9 for x, _ in admitted) > 1
                                      else "") + ".")
                decisions[place[id(d)]] = final
                return Choice(intent=intent, decision=final, decisions=decisions)
            decisions[place[id(d)]] = final
        return Choice(intent=intent, decision=None, decisions=decisions)


_guards: Dict[Tuple[Any, ...], Guard] = {}


def before_pay(offer: Any, *, pay: Optional[Callable[[str], Any]] = None, expected_price_usd: Optional[float] = None,
               category: Optional[str] = None, **options: Any) -> Decision:
    """Whether to pay this offer: the free checks, then the $0.01 signed check only where it is worth its cent.
    One Guard is kept per `pay` and set of options, so its daily cap and the pay-to addresses it has paid hold
    across calls."""
    key = (id(pay), tuple(sorted((k, repr(v)) for k, v in options.items())))
    guard = _guards.get(key)
    if guard is None or (pay is not None and (guard.paid_check is None or guard.paid_check.pay is not pay)):
        if len(_guards) >= MAX_GUARDS:   # a new pay callable on every call: keep memory bounded
            _guards.clear()
        guard = _guards[key] = Guard(pay, **options)
    return guard.decide(offer, expected_price_usd=expected_price_usd, category=category)
