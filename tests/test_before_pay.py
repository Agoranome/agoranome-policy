"""before_pay(offer) (agoranome_policy/guard.py): the free checks on every payment, and the $0.01 signed check only in the tail."""

import agoranome_policy
from agoranome_policy import Guard, before_pay
from agoranome_policy import guard as guard_lib
from agoranome_policy import policy as policy_lib

from agoranome_policy.offer import from_json
from test_policy_pack import SELLER, URL, USDC, Checker, Paying, codes, offer, verdict

AGORANOME = "https://api.agoranome.test"
CHECK_URL = AGORANOME + "/v1/buyer/check?url=https%3A%2F%2Fapi.seller.test%2Fv1%2Fsearch"


def guard(paying=None, **kwargs):
    return Guard(paying, base_url=AGORANOME, **{"checker": Checker(), **kwargs})


def test_a_first_payment_to_a_pay_to_buys_the_check_and_a_repeat_doesnt():
    paying = Paying(verdict())
    g = guard(paying)
    first = g(offer())
    assert first.allowed and first.paid_check["summary"] == "ok"
    assert first.flags[0] == "Bought Agoranome's signed Buyer check: a first payment to this pay-to address."
    assert paying.urls[0].startswith(CHECK_URL)
    again = g(offer())
    assert again.allowed and again.paid_check is None and len(paying.urls) == 1


def test_a_price_above_a_dime_or_an_unvouched_seller_buys_it_too():
    paying = Paying(verdict())
    g = guard(paying, known_pay_to=[SELLER])
    assert g(offer("10000")).paid_check is None                      # $0.01 to a known seller: no check
    above = g(offer("250000"))                                       # $0.25
    assert above.paid_check is not None and "a price above $0.1" in above.flags[0]
    down = guard(paying, known_pay_to=[SELLER], checker=Checker(fail=True))(offer())
    assert down.paid_check is not None and "couldn't vouch" in down.flags[0]


def test_without_pay_nothing_is_bought_and_the_decision_says_where_it_would_be_worth_it():
    decision = guard()(offer())
    assert decision.allowed and decision.paid_check is None
    assert any("would be worth its cent here (a first payment to this pay-to address)" in f for f in decision.flags)


def test_the_free_checks_still_refuse_and_the_check_is_never_bought_for_a_refused_offer():
    paying = Paying(verdict())
    over = guard(paying, max_price_usd=0.005)(offer())
    assert codes(over) == [policy_lib.OVER_CAP] and paying.urls == []
    listed = guard(paying, checker=Checker(listing=0.01))(offer("20000"))
    assert codes(listed) == [policy_lib.OVER_EXPECTED] and paying.urls == []


def test_a_bad_verdict_refuses_and_the_pay_to_isnt_remembered():
    paying = Paying(verdict(tiers={"any": False}))
    g = guard(paying)
    refused = g(offer())
    assert not refused.allowed and codes(refused) == [policy_lib.PAID_CHECK]
    assert SELLER.lower() not in g.known
    g(offer())
    assert len(paying.urls) == 2                                     # still a first payment: checked again


def test_the_daily_cap_holds_and_a_failed_purchase_goes_on_with_a_flag():
    paying = Paying(verdict())
    g = guard(paying, daily_cap_usd=0.01)
    g(offer())
    other = from_json({"x402Version": 2, "resource": {"url": URL},
                       "accepts": [{"scheme": "exact", "network": "eip155:8453", "asset": USDC, "amount": "10000",
                                    "payTo": "0x" + "bb" * 20}]})
    capped = g(other)
    assert capped.allowed and capped.paid_check is None and len(paying.urls) == 1
    assert any("cap" in f for f in capped.flags)
    broken = guard(Paying(fail=True))(offer())
    assert broken.allowed and any("couldn't run" in f for f in broken.flags)


def test_before_pay_takes_the_402_json_and_keeps_one_guard_per_options(monkeypatch):
    monkeypatch.setattr(guard_lib, "_guards", {})
    paying = Paying(verdict())
    data = {"x402Version": 2, "resource": {"url": URL},
            "accepts": [{"scheme": "exact", "network": "eip155:8453",
                         "asset": USDC, "amount": "10000", "payTo": SELLER}]}
    checker = Checker()
    first = before_pay(data, pay=paying, checker=checker, base_url=AGORANOME)
    second = before_pay(data, pay=paying, checker=checker, base_url=AGORANOME)
    assert first.allowed and first.paid_check is not None and second.paid_check is None
    assert len(guard_lib._guards) == 1 and len(paying.urls) == 1
    assert {"Guard", "before_pay"} <= set(agoranome_policy.__all__)


def test_a_guard_runs_in_the_x402_clients_hook():
    from agoranome_policy.x402 import hook

    class Context:
        payment_required = {"x402Version": 2, "resource": {"url": URL},
                            "accepts": [{"scheme": "exact", "network": "eip155:8453",
                                         "asset": USDC, "amount": "10000",
                                         "payTo": SELLER}]}
        selected_requirements = payment_required["accepts"][0]

    assert hook(guard(Paying(verdict())))(Context()) is None          # allowed: the payment goes ahead
    aborted = hook(guard(max_price_usd=0.001))(Context())
    assert (aborted["abort"] if isinstance(aborted, dict) else True) and aborted is not None


def test_delivery_odds_low_enough_make_a_routine_payment_worth_its_check():
    paying = Paying(verdict())
    # $0.05 to a known pay-to: at odds of 70% the expected loss, $0.015, is more than the check's cent.
    low = guard(paying, known_pay_to=[SELLER], checker=Checker(odds=0.7))(offer("50000"))
    assert low.paid_check is not None and low.delivery_odds["p"] == 0.7
    assert low.flags[0] == ("Bought Agoranome's signed Buyer check: an expected loss of $0.0150 at delivery odds of "
                            "70%, more than the check's $0.01.")
    assert low.as_dict()["delivery_odds"]["p"] == 0.7
    # At 95% the expected loss is $0.0025: the payment goes ahead without one.
    high = guard(paying, known_pay_to=[SELLER], checker=Checker(odds=0.95))(offer("50000"))
    assert high.allowed and high.paid_check is None and len(paying.urls) == 1
    # Without pay=, the decision says where it would have been worth it.
    told = guard(known_pay_to=[SELLER], checker=Checker(odds=0.7))(offer("50000"))
    assert any("would be worth its cent here (an expected loss of $0.0150" in f for f in told.flags)


def test_odds_that_arent_a_probability_are_ignored():
    for odds in (1.5, -0.1, "high", True):
        decision = guard(known_pay_to=[SELLER], checker=Checker(odds=odds))(offer("50000"))
        assert decision.delivery_odds is None and "delivery_odds" not in decision.as_dict()
        assert not any("expected loss" in f for f in decision.flags)


def test_a_memory_file_keeps_the_paid_pay_tos_between_runs(tmp_path):
    from datetime import datetime, timedelta, timezone

    path = tmp_path / "agent" / "pay-to.json"
    paying = Paying(verdict())
    first = guard(paying, memory=str(path))(offer())
    assert first.allowed and first.paid_check is not None and path.exists()
    kept = __import__("json").loads(path.read_text())
    assert kept["format"] == guard_lib.MEMORY_FORMAT and list(kept["pay_to"]) == [SELLER.lower()]
    # The next run, a new guard on the same file: no check for a pay-to it paid.
    later = guard(paying, memory=str(path))
    assert SELLER.lower() in later.known and later(offer()).paid_check is None and len(paying.urls) == 1
    # A month without a payment: checked again.
    month = guard_lib.Memory(path, clock=lambda: datetime.now(timezone.utc) + timedelta(days=31))
    assert month.known() == set()
    # Forgetting one (a payment that didn't go through) takes it out of the file too.
    later.forget(SELLER)
    assert SELLER.lower() not in later.known and guard_lib.Memory(path).known() == set()


def test_the_memory_never_stops_a_payment_and_never_overwrites_a_file_it_didnt_write(tmp_path, monkeypatch):
    foreign = tmp_path / "notes.json"
    foreign.write_text('{"mine": true}')
    decided = guard(memory=str(foreign))(offer())
    assert decided.allowed and foreign.read_text() == '{"mine": true}'
    assert any("Pay-to memory not kept" in f and "isn't a pay-to memory file" in f for f in decided.flags)
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    assert guard(memory=str(broken))(offer()).allowed
    blocked = tmp_path / "file-not-dir"
    blocked.write_text("x")
    stuck = guard(memory=str(blocked / "pay-to.json"))(offer())
    assert stuck.allowed and any("couldn't write" in f for f in stuck.flags)
    # The environment variable names the file when the argument doesn't; refused offers are never remembered.
    env = tmp_path / "env.json"
    monkeypatch.setenv(guard_lib.MEMORY_ENV, str(env))
    assert guard(max_price_usd=0.005)(offer()).allowed is False and not env.exists()
    assert guard()(offer()).allowed and SELLER.lower() in guard_lib.Memory(env).known()
