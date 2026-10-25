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
