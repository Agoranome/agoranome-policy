# agoranome-policy

A buyer's policy for x402 payments: pay only for offers that show the proof you ask for.

Every buyer runtime ships spend controls (a cap, a payee allowlist) and leaves the
question of *which seller* to the client. This package answers it. It sits in front
of an x402 client, and before each payment it checks:

1. **Price**: no more than your cap, and no more than the listing or the quote.
2. **Payee**: on your allowlist, when you keep one.
3. **Instructions**: no text in the offer written to steer an agent.
4. **Proof**: your tier, read from the seller's Fair Offer block and, by default,
   from Agoranome's free checker, which verifies the claims from outside.

It sends an `Accept-Proof` header with every unpaid request, keeps signed receipts
on your machine, and flags instruction-like text in paid answers. It has no
dependencies beyond the Python standard library.

## Tiers

| Tier | Accept-Proof it sends | Pays when |
| --- | --- | --- |
| `any` | (none) | price and payee checks pass |
| `sampled` | `sample=any; instructions=none` | the seller offers a free sample and declares data, never instructions |
| `delivered` | `sample=any; instructions=none; receipts=signed; deliveries_30d>=5` | as `sampled`, plus signed receipts and at least 5 verified deliveries in 30 days |

Raw payer counts are never used. Sweep bots pay every seller once, so a high payer
count says nothing about delivery. "Delivered" counts deliveries reconciled against
the chain to wallets that aren't sweeps, from the
[evidence commons](https://agoranome.com/commons).

## Use it

### With the x402 Python SDK

```python
from x402 import x402Client
from agoranome_policy import Policy
from agoranome_policy.x402 import install

policy = Policy("sampled", max_price_usd=0.05, checker=True)
client = install(x402Client(), policy)        # refused offers are never signed
headers = policy.headers()                    # send these with each unpaid request
```

### Choosing among candidates

```python
choice = policy.choose("convert a PDF to Markdown", offers)
if choice.found:
    pay(choice.decision.option)
```

When no candidate is admissible and you've opted into telemetry, the intent is
reported as unmet (see below).

### As a Claude Code hook

```json
{"hooks": {
  "PreToolUse":  [{"matcher": "mcp__.*(pay|x402|paid|fetch).*|Bash",
                   "hooks": [{"type": "command", "command": "agoranome-policy hook pre"}]}],
  "PostToolUse": [{"matcher": "mcp__.*(pay|x402|paid|fetch).*|Bash",
                   "hooks": [{"type": "command", "command": "agoranome-policy hook post"}]}]}}
```

Before a paying tool runs, the hook reads the 402 without paying and denies the call
when the offer falls short. If the offer can't be read, the hook asks you rather
than guessing. After the call it writes a signed receipt and warns Claude if the
answer contains instruction-like text. Set `AGORANOME_POLICY_TIER`,
`AGORANOME_POLICY_MAX_PRICE` and the other settings listed in `claude_code.py`.

### From the command line

```sh
agoranome-policy check https://api.example.com/v1/search --tier delivered
agoranome-policy export cdp --pay-to 0xYourSeller --max-price 0.05   # CDP wallet policy
agoranome-policy export cloudflare --tier sampled                    # withX402Client callback
agoranome-policy receipts verify ~/.config/agoranome-policy/receipts.jsonl
```

The CDP export is a Coinbase Developer Platform wallet policy. Once it's attached to
your account, the wallet signs x402 payments only to your payees, only in USDC and
only up to your cap, even if the agent's code is wrong.

### From an MCP client

Agoranome's MCP server at `https://api.agoranome.com/mcp` has a free `check_offer`
tool that runs the same decision on its side.

## One call before paying: `before_pay`

```python
from agoranome_policy import Guard

guard = Guard(pay=lambda url: paying.get(url).json())   # your x402 client performs the paid GET
decision = guard(offer)                                  # an Offer, or the 402's decoded JSON
if decision.allowed:
    pay(decision.option)
```

The free checks run on every payment: price against your cap and the listing,
payee, instruction-like text, and Agoranome's free checker. Agoranome's signed
Buyer check (free since 11 November 2026; it cost $0.01 before) is asked for only
in the tail, where it adds most. The rule below still uses a cent as the bar, so a
routine payment isn't slowed by a second call:

- a first payment to a pay-to address the guard hasn't paid;
- a price above a dime;
- an expected loss above the check's cent: (1 - p) x price > $0.01, where p is the
  seller's delivery odds from the free checker (a probability with a 95% range;
  null when Agoranome holds no evidence on the seller and no base rate yet, which
  this rule then leaves to the others);
- a seller the free checker couldn't vouch for.

A routine repeat payment of a few cents to a known seller pays without one.
Without `pay=`, nothing is bought, and the decision says where a check would
have been worth it. Keep one guard for an agent's run so its daily cap ($0.05,
five checks) and the pay-to addresses it has paid hold across calls.
`before_pay(offer, pay=...)` does this with one guard per set of options, and
`install(client, guard)` runs a guard in the x402 client's before-payment hook.

To keep the pay-to addresses between runs, give the guard a file:

```python
guard = Guard(pay=..., memory="~/.agoranome/pay-to.json")   # or set AGORANOME_POLICY_MEMORY
```

A pay-to is remembered when the guard allows a payment to it, for 30 days after
the last one (`memory_days=`), so a seller you haven't paid in a month is checked
again. `guard.forget(pay_to)` drops one whose payment didn't go through. The file
holds only addresses and dates. A file that can't be read or written never stops
a payment: the guard works from memory and the decision flags it, and a file it
didn't write is never overwritten.

### Learning from your own payments

Give the guard a receipt log and tell it how each payment went:

```python
guard = Guard(pay=..., receipts="~/.agoranome/receipts.jsonl")
decision = guard(offer)
if decision.allowed:
    response = paying.get(url)                       # your x402 client pays
    guard.record(decision, status=response.status_code, settled=True, response=response.content)
```

The guard keeps a private Beta per pay-to from its own signed receipts: a
settled payment answered 2xx at no more than the price expected counts good,
any other settled payment counts bad. It joins that with Agoranome's delivery
odds by precision weighting, Agoranome's evidence counting as at most ten
observations, so after about ten calls your own experience leads:

    a = good + n p,   b = bad + n (1 - p),   n = min(observations, 10)

`decision.own_odds` shows the result, and the expected-loss rule above reads it,
so a seller that keeps failing you is checked again even when it's known. A
receipt whose signature doesn't check is not counted. Nothing of the record
leaves your machine; telemetry never carries it.

`guard.choose(offers)` picks the cheapest offer the guard allows. Among
admissible offers at the same price, it draws once from each one's Beta and
tries them in the order of the draws (Thompson sampling): a seller that has
served you well is tried first more often, and a new one still gets its turn.
The free checks run on every candidate; a check is bought, where one is worth
its cent, only for the offer about to be paid.

## Claim labels: `annotate(offer)`

```python
from agoranome_policy import annotate

for claim in annotate(offer, counts={"payers_30d": 40}):
    print(claim["kind"], claim["status"], claim["text"])
```

Each claim an offer's own words make, tagged by kind (count, standing,
endorsement, urgency, authority, pledge, instruction) and status: `verified`
(the Bazaar's own 30-day count agrees within 10%, or a record you pass in
does), `unverified`, `contradicted` (a 30-day payer or call count the Bazaar's
own count is more than 10% below), or `steering` (urgency and instructions).
Nothing is stripped: give your model the label beside the text. An honest
seller's true but unprovable claim reads "unverified", never "false". The free
checker's `listing` holds the counts. The same rules label the claims in
Agoranome's signed Buyer check.

## A referee's own rules: `referee(url)`

```python
from agoranome_policy import referee

found = referee("https://agoranome.com/.well-known/fair-referee.json")
if found["signed"]:
    print([rule["id"] for rule in found["rules"]])
```

A referee of x402 sellers (Agoranome, or anyone who publishes a file of the same
shape) states the rules it binds itself to at `/.well-known/fair-referee.json`:
no paid placement, every qualifying seller listed, sort keys stated, methods and
coefficients published, its own offers under the same probes and grades, each
with how to check it. `referee()` reads the file and checks its JWS signatures
against the keys at the same site's `/.well-known/jwks.json` (a key set on
another site is never read). EdDSA is checked with the standard library alone;
ES256K and ES256 are checked when the `cryptography` package is installed, and
reported as not checked otherwise. `signed` is True when one signature checks.

## A signed verdict, free: off unless you opt in

The free check reads the seller's live 402 and is unsigned. Agoranome's
[Buyer check](https://agoranome.com/lab#buyer_check) (free since 11 November 2026;
it was $0.01, and an answer that still carries a receipt counts $0.01 against your
daily cap) answers from its
stored evidence in about a second with a signed verdict: block valid and
certified, the pay-to seen for the host and since when, price against listing and
quote, verified deliveries, and which tiers the offer meets. The pack can ask for
it when the seller is unknown to the free check, or the price is above your
threshold, within a daily cap. Asking is any GET; your own x402 client passes the
free answer through:

```python
from agoranome_policy import PaidCheck, Policy

paying = x402HttpxClient(account=my_account)   # any client that performs a paid GET
policy = Policy("sampled", checker=True,
                paid_check=PaidCheck(lambda url: paying.get(url).json(),
                                     when="unknown_or_above", above_usd=0.10, daily_cap_usd=0.05))
```

The policy refuses when the verdict says your tier is not met or a Fair Offer rule
is contradicted, flags a pay-to that changed in 30 days, and keeps the verdict on
the decision (`decision.paid_check`). If the check can't be bought, the decision
goes on without it and says so. After paying, the same route with `tx=` returns
settlement proof; with `share=true` your receipt enters the evidence commons.

## Agoranome's admission feed as your allowlist

Most runtimes ship a payee allowlist and leave it blank. Agoranome's free, signed
[admission feed](https://agoranome.com/machines/admission) lists, by category, the
sellers that meet published rules, in three tiers from the widest: **sheet** (on
the Agoranome inspector's newest signed sheet, every offer asked what its listing
shows and paid an address the listing names, with no paid test; served when
asked), **observed** (Agoranome's own paid probe delivered, the live price and
pay-to match the listing, no OFAC match) and **certified** (observed, plus a Fair
Offer certification passed in 30 days). Certification is no longer sold, so the
certified tier empties as the last certificates age out. A tier admits the tiers
above it. Admission is never sold and the feed never ranks sellers.

```python
from agoranome_policy import AdmissionFeed, Policy

feed = AdmissionFeed.from_url()                              # read it again daily
policy = Policy("any", allow_pay_to=feed.payees())           # observed and certified
wide = AdmissionFeed.from_url(tier="sheet")                  # hundreds of sellers, no paid test
policy = Policy("any", allow_pay_to=wide.payees("sheet"))
feed.in_category("web_search")                               # the admitted hosts, by host
```

The feed is signed (JWS over its RFC 8785 form, keys at
`https://agoranome.com/.well-known/jwks.json`); check the signatures with a JOSE
library before loading it into a wallet. It also comes as a Coinbase Developer
Platform wallet policy, a Cloudflare Agents callback and a Cedar policy.

## Expected-loss mode: pay for evidence only when it's worth it

Instead of a fixed tier, decide each payment by value of information. The
category's prior chance of loss comes from Agoranome's free
[base rates](https://agoranome.com/machines/base-rates); the seller's own evidence
(its admission tier, a verified sample, verified deliveries, a contradicted rule)
updates it; expected loss is the price times the result.

```python
from agoranome_policy import AdmissionFeed, BaseRates, ExpectedLoss, PaidCheck, Policy

policy = Policy("any", checker=True,
                expected_loss=ExpectedLoss(BaseRates.from_url(), admission=AdmissionFeed.from_url(),
                                           check_cost_usd=0.01, refuse_above=0.5),
                paid_check=PaidCheck(lambda url: paying.get(url).json()))
decision = policy.decide(offer, category="web_search")
decision.loss   # {"action": "pay" | "check_first" | "refuse", "posterior": ..., "expected_loss_usd": ...}
```

It pays when the expected loss is no more than `check_cost_usd`, asks for the
signed check first when the loss is larger (or refuses with `check_first` when no
`paid_check` is set), and refuses when a loss is more likely than `refuse_above`.
A $0.005 chain read from an observed seller needs nothing; a $1 call to an unseen
host is worth a check first.

When the free checker gives the seller's delivery odds (Agoranome's posterior from
its paid probes, reconciled deliveries, returning buyers and settlement proofs,
each counting less as it ages), the chance of loss is the larger of `1 - p` and
the posterior above. The odds can only add caution here, never remove it.

## Telemetry: off unless you opt in

Pass `telemetry=Reporter(consent=True)` or set `AGORANOME_POLICY_TELEMETRY=1`. You
then send two anonymized kinds of event to Agoranome's public indexes:

- **admission**: the proof your policy asked of an offer, the offer's category and
  host, and whether it passed. This feeds the
  [admission index](https://api.agoranome.com/v1/policy/admission).
- **unmet_intent**: what you tried to buy when nothing passed, and why. This feeds the
  [unmet-intent index](https://api.agoranome.com/v1/policy/unmet-intents).

Nothing identifies you: no wallet, no URL path, no time finer than the day. A random
install id counts installs. Intent text has emails, URLs, addresses and long numbers
removed and is cut to 160 characters, and an intent is published only once two
installs have reported it. The schema is
[policy-telemetry-0.1](https://agoranome.com/standard/policy-telemetry-0.1.schema.json).

## Licence

Apache-2.0.
