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

"""0.9.1: the two faults the validation of 17 Nov 2026 found in 0.9.0, each pinned by a test.

1. The fallback to the inspector's signed sheet never read a real sheet. The sheet used the checker's reader, which
   stopped at 1,000,000 bytes, and the published sheet is about 9.4 MB, so the SHA-256 never matched and an
   overcharge was allowed with a flag. The tests of 0.9.0 passed because each swapped in its own reader. The tests
   here serve the files from a local HTTP server and read them with the reader the package ships.
2. The guard read USDC on 6 networks and the inspector's rule sheet-2 on 10, so a listing priced in USDC on Solana,
   Avalanche, World Chain or Monad was refused as "price isn't in USDC". The two lists are pinned together here.
"""

import contextlib
import hashlib
import http.server
import json
import threading

import pytest

from agoranome_policy import InspectorSheet, Policy, SheetError, offer as offer_lib
from agoranome_policy import policy as policy_lib
from agoranome_policy import sheet as sheet_lib
from agoranome_policy.evidence import MAX_ANSWER_BYTES, urllib_get
from agoranome_policy.offer import from_json
from test_facts_tier import KEY, _entry
from test_policy_pack import BASE, SELLER, URL, USDC, Checker, codes, offer

SHEET_ID = "x402-2026-11-16"


# --- A local copy of the inspector's site, served over HTTP -----------------------------------------------------------

def big_site(filler_rows=6000, extra_listed=()):
    """book.jsonl and a sheet well over 1 MB, signed from KEY, as the inspector publishes them."""
    rows = [{"resource": URL, "host": "api.seller.test", "category": "web_search",
             "listed": [{"network": "base", "asset": USDC.lower(), "amount": "10000", "pay_to": SELLER.lower(),
                         "scheme": "exact"}, *extra_listed],
             "seen": None, "verdict": {"matches_listing": True}}]
    rows += [{"resource": f"https://filler-{i}.example/v1/item", "host": f"filler-{i}.example", "category": "other",
              "listed": [{"network": "eip155:8453", "asset": USDC.lower(), "amount": str(1000 + i),
                          "pay_to": "0x" + f"{i:040x}", "scheme": "exact"}],
              "seen": None, "verdict": {"matches_listing": True}} for i in range(filler_rows)]
    sheet = (json.dumps({"id": SHEET_ID, "rule": "sheet-2", "rows": rows}) + "\n").encode()
    entries = [_entry(0, "0x" + "00" * 32, "key", {"key": KEY.jwk}, KEY)]
    body = {"id": SHEET_ID, "market": "x402", "file": f"sheets/{SHEET_ID}.json", "rule": "sheet-2",
            "sha256": "0x" + hashlib.sha256(sheet).hexdigest()}
    entries.append(_entry(1, entries[-1]["hash"], "sheet", body, KEY))
    return {"/book.jsonl": "\n".join(json.dumps(e) for e in entries).encode(),
            f"/sheets/{SHEET_ID}.json": sheet}


@contextlib.contextmanager
def served(files):
    """An HTTP server on 127.0.0.1 that answers GETs for these paths, and the base URL of the site."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):   # noqa: N802 (the stdlib's name)
            body = files.get(self.path)
            self.send_response(200 if body is not None else 404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body or b"")))
            self.end_headers()
            self.wfile.write(body or b"")

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()


# --- 1. The sheet fallback reads the whole sheet --------------------------------------------------------------------

def test_the_shipped_reader_reads_a_sheet_over_1_mb_and_the_guard_refuses_an_overcharge(tmp_path):
    files = big_site()
    assert len(files[f"/sheets/{SHEET_ID}.json"]) > 1_000_000, "the fixture must be larger than 0.9.0's cap"
    with served(files) as site:
        sheet = InspectorSheet(site, first_key=KEY.jwk, cache_dir=str(tmp_path), timeout=10.0)   # no get=: real reader
        policy = Policy(checker=Checker(fail=True), sheet=sheet)
        over = policy.decide(offer("20000"))
        assert codes(over) == [policy_lib.OVER_EXPECTED], over.summary
        assert over.listing_source == f"sheet {SHEET_ID}"
        assert policy.decide(offer("10000")).allowed
    assert len(sheet.index()["rows"]) == 6001


def test_with_the_real_reader_refuse_mode_pays_an_honest_offer_from_the_sheet():
    with served(big_site()) as site:
        sheet = InspectorSheet(site, first_key=KEY.jwk, timeout=10.0)
        decision = Policy(checker=Checker(fail=True), sheet=sheet, on_checker_down="refuse").decide(offer())
    assert decision.allowed and decision.listing_source == f"sheet {SHEET_ID}"


def test_a_sheet_larger_than_the_limit_is_refused_as_too_large_not_as_a_wrong_file(monkeypatch):
    monkeypatch.setattr(sheet_lib, "MAX_SHEET_BYTES", 500_000)
    with served(big_site()) as site:
        with pytest.raises(SheetError, match="larger than 500000 bytes"):
            InspectorSheet(site, first_key=KEY.jwk, timeout=10.0).listing(URL)


def test_the_checkers_reader_still_stops_at_1_mb_and_a_limit_is_a_limit():
    body = b"x" * 1_500_000
    with served({"/big": body, "/small": b"{}"}) as site:
        assert urllib_get(10.0)(site + "big") == (200, body[:MAX_ANSWER_BYTES])
        assert urllib_get(10.0, limit=1_500_001)(site + "big") == (200, body)
        assert urllib_get(10.0, limit=10)(site + "small") == (200, b"{}")
        assert urllib_get(10.0)(site + "missing")[0] == 404


# --- 2. The guard's dollars are sheet-2's ---------------------------------------------------------------------------

# The inspector's rule sheet-2 judges price on these (network, asset) pairs, its DOLLAR list, frozen with the rule
# (agoranome-inspector, src/agoranome_inspector/rule2.py). A published rule never changes, so the copy here is the
# list; a new token on the inspector's side is a new rule, and this test is where the guard catches up with it.
SHEET_2_DOLLAR = {
    ("eip155:8453", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"),     # Base
    ("eip155:84532", "0x036cbd53842c5426634e7929541ec2318f3dcf7e"),    # Base Sepolia
    ("eip155:1", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),        # Ethereum
    ("eip155:137", "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359"),      # Polygon
    ("eip155:42161", "0xaf88d065e77c8cc2239327c5edb3a432268e5831"),    # Arbitrum
    ("eip155:10", "0x0b2c639c533813f4aa9d7837caf62653d097ff85"),       # Optimism
    ("eip155:43114", "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e"),    # Avalanche
    ("eip155:480", "0x79a02482a880bce3f13e09da970dc34db4cd24d1"),      # World Chain
    ("eip155:143", "0x754704bc059f8c67012fed69bc8a327a5aafb603"),      # Monad
    ("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),   # Solana
}
SOLANA = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
SOLANA_USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
SOLANA_SELLER = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"


def test_the_guards_usdc_list_is_sheet_2s_dollar_list():
    assert set(offer_lib.USDC.items()) == SHEET_2_DOLLAR
    for network, asset in SHEET_2_DOLLAR:
        assert offer_lib.is_usdc(network, asset)
        if asset.startswith("0x"):
            assert offer_lib.is_usdc(network, asset.upper().replace("0X", "0x")), "EVM contracts ignore case"


def solana_offer(amount="10000", asset=SOLANA_USDC, network=SOLANA, pay_to=SOLANA_SELLER):
    return from_json({"x402Version": 2, "resource": {"url": URL, "description": "Web search results as JSON."},
                      "accepts": [{"scheme": "exact", "network": network, "asset": asset, "amount": amount,
                                   "payTo": pay_to}]})


def test_usdc_on_the_four_added_networks_is_read_as_dollars():
    for network, asset in [("eip155:43114", "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E"),
                           ("eip155:480", "0x79A02482A880bCE3F13e09Da970dC34db4CD24d1"),
                           ("eip155:143", "0x754704Bc059F8C67012fEd69BC8A327a5aafb603"),
                           (SOLANA, SOLANA_USDC)]:
        decision = Policy("any").decide(solana_offer(network=network, asset=asset))
        assert decision.allowed and decision.price_usd == 0.01, (network, decision.summary)
    # A Solana mint is case-sensitive: the same letters in lower case are another token.
    assert codes(Policy("any").decide(solana_offer(asset=SOLANA_USDC.lower()))) == [policy_lib.NOT_USDC]
    # x402 v1 names map to the same networks.
    assert from_json({"x402Version": 1, "accepts": [{"scheme": "exact", "network": "solana", "asset": SOLANA_USDC,
                                                     "maxAmountRequired": "10000", "payTo": SOLANA_SELLER,
                                                     "resource": URL}]}).options[0].price_usd == 0.01
    assert from_json({"x402Version": 1, "accepts": [{"scheme": "exact", "network": "avalanche",
                                                     "asset": "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e",
                                                     "maxAmountRequired": "10000", "payTo": SELLER,
                                                     "resource": URL}]}).options[0].is_usdc


def test_a_solana_listing_on_the_sheet_refuses_an_overcharge_and_another_payee(tmp_path):
    listed = [{"network": SOLANA, "asset": SOLANA_USDC, "amount": "10000", "pay_to": SOLANA_SELLER, "scheme": "exact"}]
    with served(big_site(filler_rows=10, extra_listed=listed)) as site:
        sheet = InspectorSheet(site, first_key=KEY.jwk, timeout=10.0)
        policy = Policy(checker=Checker(fail=True), sheet=sheet)
        assert policy.decide(solana_offer()).allowed
        assert codes(policy.decide(solana_offer("20000"))) == [policy_lib.OVER_EXPECTED]
        other = "7" + SOLANA_SELLER[1:]
        assert codes(policy.decide(solana_offer(pay_to=other))) == [policy_lib.PAYEE_LISTING]
    listing = sheet.listing(URL)
    assert listing.price_usd(SOLANA) == 0.01 and listing.payees(SOLANA) == [SOLANA_SELLER]


def test_the_cdp_export_names_only_evm_contracts():
    from agoranome_policy import exports

    contracts = exports.cdp_policy([SELLER], networks=[BASE, SOLANA])["rules"][0]["criteria"][0]["addresses"]
    assert contracts == [offer_lib.USDC[BASE]]
    with pytest.raises(ValueError, match="no USDC contract"):
        exports.cdp_policy([SELLER], networks=[SOLANA])
