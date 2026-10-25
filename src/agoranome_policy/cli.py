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

"""agoranome-policy: check an offer, run as a Claude Code hook, or export the rules.

    agoranome-policy check https://api.example.com/v1/search --tier delivered
    agoranome-policy hook pre        (Claude Code PreToolUse; reads the event on stdin)
    agoranome-policy hook post       (Claude Code PostToolUse)
    agoranome-policy export cdp --pay-to 0xabc... --max-price 0.05
    agoranome-policy export cloudflare --tier sampled
    agoranome-policy receipts verify ~/.config/agoranome-policy/receipts.jsonl
"""

import argparse
import json
import sys
from typing import List, Optional

from agoranome_policy import __version__, claude_code, exports
from agoranome_policy.policy import Policy
from agoranome_policy.proof import TIERS
from agoranome_policy.receipts import ReceiptLog
from agoranome_policy.telemetry import Reporter


def _policy(args: argparse.Namespace) -> Policy:
    return Policy(args.tier, max_price_usd=args.max_price, min_deliveries=args.min_deliveries,
                  allow_pay_to=args.pay_to or None, checker=True if not args.no_checker else None,
                  telemetry=Reporter.from_env())


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="agoranome-policy", description=__doc__.split("\n")[0])
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    def rules(p: argparse.ArgumentParser) -> None:
        p.add_argument("--tier", choices=TIERS, default="sampled")
        p.add_argument("--max-price", type=float, default=1.0, help="dollars per call")
        p.add_argument("--min-deliveries", type=int, default=5)
        p.add_argument("--pay-to", action="append", default=[], help="allowed payee (repeat)")
        p.add_argument("--no-checker", action="store_true", help="read only the seller's own block")

    check = sub.add_parser("check", help="decide whether to pay one offer, without paying")
    check.add_argument("url")
    check.add_argument("--expected-price", type=float, help="the listing's or quote's price in dollars")
    rules(check)

    hook = sub.add_parser("hook", help="run as a Claude Code hook (event JSON on stdin)")
    hook.add_argument("mode", choices=("pre", "post"))

    export = sub.add_parser("export", help="the same rules for other runtimes")
    export.add_argument("target", choices=("cdp", "cloudflare"))
    rules(export)

    receipts = sub.add_parser("receipts", help="check a local receipts file's signatures")
    receipts.add_argument("action", choices=("verify",))
    receipts.add_argument("path")

    args = parser.parse_args(argv)
    if args.command == "hook":
        return claude_code.main(args.mode)
    if args.command == "check":
        policy = _policy(args)
        offer = claude_code.fetch_offer(args.url, policy)
        if offer is None:
            print(json.dumps({"url": args.url, "offer": None, "summary": "No x402 offer: nothing to pay."}))
            return 0
        decision = policy.decide(offer, expected_price_usd=args.expected_price)
        print(json.dumps(decision.as_dict(), indent=2))
        if policy.telemetry is not None:
            policy.telemetry.flush()
        return 0 if decision.allowed else 2
    if args.command == "export":
        policy = _policy(args)
        if args.target == "cdp":
            print(json.dumps(exports.cdp_policy_for(policy), indent=2))
        else:
            sys.stdout.write(exports.cloudflare_snippet(policy))
        return 0
    log = ReceiptLog(args.path)
    lines = list(log)
    bad = [i + 1 for i, line in enumerate(lines) if not log.verify(line)]
    print(json.dumps({"receipts": len(lines), "valid": len(lines) - len(bad), "invalid_lines": bad}))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
