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

"""The admission feed as an allowlist, and expected-loss mode: pay for evidence only when the loss it could prevent
is worth more than it costs."""

import pytest

import agoranome_policy
from agoranome_policy import AdmissionFeed, BaseRates, Evidence, ExpectedLoss, Policy, policy as policy_lib
from agoranome_policy.expected_loss import CHECK_FIRST, PAY, REFUSE, evidence_from_rules
from agoranome_policy.paid import PaidCheck

from test_policy_pack import KEPT, SELLER, Checker, Paying, codes, offer, verdict

FEED = {"feed": "Agoranome admission feed", "day": "2026-11-02", "sellers": [
    {"host": "api.seller.test", "tier": "certified", "categories": ["web_search"], "pay_to": ["0x" + SELLER[2:].upper()],
     "networks": ["eip155:8453"]},
    {"host": "geo.example", "tier": "observed", "categories": ["weather_geo", "web_search"], "pay_to": ["0x" + "bb" * 20],
     "networks": ["eip155:8453"]},
    {"host": "testnet.example", "tier": "observed", "categories": ["other"], "pay_to": ["0x" + "cc" * 20],
     "networks": ["eip155:84532"]},
    {"host": "bad.example", "tier": "observed", "categories": [], "pay_to": ["not an address"]},
]}


def test_the_admission_feed_reads_as_an_allowlist_by_tier_network_and_category():
    feed = AdmissionFeed(FEED)
    assert feed.day == "2026-11-02"
    assert feed.tier_of("https://API.seller.test./v1/search") == "certified" and feed.tier_of("geo.example") == "observed"
    assert feed.tier_of("nobody.example") is None
    assert feed.payees() == [SELLER, "0x" + "bb" * 20], "lowercased, Base only, addresses only"
    assert feed.payees("certified") == [SELLER] and feed.payees(network="eip155:84532") == ["0x" + "cc" * 20]
    assert feed.admits(SELLER.upper().replace("0X", "0x")) and feed.admits(SELLER, host="api.seller.test")
    assert not feed.admits(SELLER, host="geo.example") and not feed.admits("0x" + "bb" * 20, tier="certified")
    assert feed.in_category("web_search") == ["api.seller.test", "geo.example"]
    assert feed.in_category("web_search", tier="certified") == ["api.seller.test"]
    with pytest.raises(ValueError):
        feed.payees("best")
    with pytest.raises(ValueError):
        AdmissionFeed({"sellers": "none"})
    # As the pack's payee allowlist.
    assert Policy("any", allow_pay_to=feed.payees()).decide(offer()).allowed
    refused = Policy("any", allow_pay_to=feed.payees()[1:]).decide(offer())
    assert codes(refused) == [policy_lib.PAYEE]


def test_the_posterior_starts_from_the_prior_and_moves_with_each_piece_of_evidence():
    assert ExpectedLoss.posterior(0.2, Evidence()) == pytest.approx(0.2)
    assert ExpectedLoss.posterior(0.2, Evidence(tier="observed")) == pytest.approx(2 / 13)
    assert ExpectedLoss.posterior(0.2, Evidence(tier="certified")) == pytest.approx(2 / 16)
    assert ExpectedLoss.posterior(0.2, Evidence(sampled=True, deliveries_30d=7)) == pytest.approx(2 / 18)
    assert ExpectedLoss.posterior(0.2, Evidence(deliveries_30d=500)) == ExpectedLoss.posterior(
        0.2, Evidence(deliveries_30d=30)) == pytest.approx(2 / 40), "deliveries count up to 30"
    assert ExpectedLoss.posterior(0.2, Evidence(deliveries_30d=-4)) == pytest.approx(0.2)
    assert ExpectedLoss.posterior(0.2, Evidence(contradicted=True)) == pytest.approx(10 / 18)


@pytest.mark.parametrize("price, evidence, action", [
    (0.005, Evidence(), PAY),                        # a half-cent call from anyone: the check costs more than the risk
    (1.0, Evidence(), CHECK_FIRST),                  # a dollar to an unseen host: a cent's check is worth it
    (0.05, Evidence(tier="observed"), PAY),
    (0.10, Evidence(tier="observed"), CHECK_FIRST),
    (0.08, Evidence(tier="certified"), PAY),
    (1.0, Evidence(contradicted=True), REFUSE),
    (0.001, Evidence(contradicted=True, tier="certified"), PAY),
])
def test_pay_check_first_or_refuse_by_expected_loss(price, evidence, action):
    assert ExpectedLoss().decide(price, evidence=evidence).action == action


def test_the_prior_comes_from_the_base_rates_by_category_and_the_decision_says_where():
    rates = BaseRates({"categories": [{"key": "web_search", "prior_loss": {"value": 0.1}},
                                      {"key": "risky", "prior_loss": {"value": 0.6}},
                                      {"key": "broken", "prior_loss": {"value": 2}}],
                       "all": {"prior_loss": {"value": 0.3}}})
    assert rates.prior("web_search") == 0.1 and rates.prior("broken") == 0.3 and rates.prior(None) == 0.3
    loss = ExpectedLoss(rates)
    search = loss.decide(0.05, category="web_search")
    assert (search.prior, search.prior_source, search.action) == (0.1, "base rates", PAY)
    assert loss.decide(0.01, category="risky").action == REFUSE, "a likely loss is refused at any price"
    unread = ExpectedLoss(BaseRates({"categories": [], "all": {"prior_loss": None}})).decide(0.05)
    assert (unread.prior, unread.prior_source) == (0.2, "default")
    shown = loss.decide(1.0, category="web_search").as_dict()
    assert shown["action"] == CHECK_FIRST and shown["expected_loss_usd"] == pytest.approx(0.1, abs=1e-6)
    assert shown["summary"] == "Check first: expected loss $0.1000 (chance 10.0%) is more than a $0.01 check."
    assert ExpectedLoss().decide(0.005).summary == ("Pay: expected loss $0.0010 (chance 20.0%) is no more than a "
                                                    "$0.01 check.")
    assert ExpectedLoss().decide(1, evidence=Evidence(contradicted=True)).summary == \
        "Refuse: the chance of loss, 55.6%, is too high."
    with pytest.raises(ValueError):
        ExpectedLoss(refuse_above=0)


def test_a_sellers_tier_in_the_admission_feed_counts_as_evidence():
    loss = ExpectedLoss(admission=AdmissionFeed(FEED))
    certified = loss.decide(0.08, host="https://api.seller.test/v1/search")
    assert certified.evidence["tier"] == "certified" and certified.action == PAY
    assert loss.decide(0.08, host="https://nobody.example/x").action == CHECK_FIRST
    assert evidence_from_rules({"FO-4": {"status": "verified"}, "FO-2": "contradicted"}, 3) == Evidence(
        sampled=True, deliveries_30d=3, contradicted=True)
    assert evidence_from_rules({}, None) == Evidence()


class Contradicting(Checker):
    def check(self, url, accept_proof=None):
        found = super().check(url, accept_proof)
        found["rules"]["FO-2"] = {"status": "contradicted"}
        return found


def test_the_policy_in_expected_loss_mode_pays_checks_first_or_refuses():
    known = Policy("any", checker=Checker(deliveries=7), expected_loss=ExpectedLoss()).decide(offer())
    assert known.allowed and known.as_dict()["loss"]["action"] == PAY
    assert known.loss["evidence"] == {"tier": None, "sampled": True, "deliveries_30d": 7, "contradicted": False}
    # A dollar to a seller nobody has seen: check first, and without a paid check, don't pay.
    dollar = offer(amount="1000000", info=KEPT)
    unknown = Policy("any", expected_loss=ExpectedLoss()).decide(dollar)
    assert codes(unknown) == [policy_lib.CHECK_FIRST]
    assert unknown.reasons[0]["detail"] == ("expected loss $0.2000 (chance 20.0%) is more than a $0.01 check; buy "
                                            "Agoranome's signed Buyer check before paying")
    # With the paid check on, it's bought and read at the sampled tier.
    paying = Paying(verdict())
    checked = Policy("any", expected_loss=ExpectedLoss(),
                     paid_check=PaidCheck(paying, daily_cap_usd=1.0)).decide(dollar)
    assert checked.allowed and checked.paid_check["summary"] == "ok" and len(paying.urls) == 1
    failing = Policy("any", expected_loss=ExpectedLoss(), paid_check=PaidCheck(
        Paying(verdict(tiers={"any": True, "sampled": False, "delivered": False})))).decide(dollar)
    assert codes(failing) == [policy_lib.PAID_CHECK]
    spent = PaidCheck(Paying(verdict()), daily_cap_usd=0.0)
    broke = Policy("any", expected_loss=ExpectedLoss(), paid_check=spent).decide(dollar)
    assert codes(broke) == [policy_lib.CHECK_FIRST] and "couldn't be bought" in broke.reasons[0]["detail"]
    # A contradicted rule with nothing to set against it: refused, whatever the price.
    contradicted = Policy("any", checker=Contradicting(deliveries=0), expected_loss=ExpectedLoss()).decide(offer())
    assert codes(contradicted) == [policy_lib.LOSS] and contradicted.reasons[0]["detail"] == \
        "the chance of loss, 52.6%, is too high"
    # Other refusals still come first, and the loss isn't read once one stands.
    over = Policy("any", max_price_usd=0.5, expected_loss=ExpectedLoss()).decide(dollar)
    assert codes(over) == [policy_lib.OVER_CAP] and over.loss is None


def test_expected_loss_replaces_the_tiers_proof_rules_but_nothing_else():
    bare = offer()   # no Fair Offer block: fails the sampled tier
    assert not Policy("sampled").decide(bare).allowed
    decided = Policy("sampled", expected_loss=ExpectedLoss()).decide(bare)
    assert decided.allowed and decided.loss["action"] == PAY and decided.unmet, "still shown, no longer refused"
    assert agoranome_policy.__version__ == "0.6.0"
    assert {"AdmissionFeed", "BaseRates", "Evidence", "ExpectedLoss"} <= set(agoranome_policy.__all__)


def test_the_free_checkers_delivery_odds_only_add_caution():
    good = Evidence(tier="certified", deliveries_30d=30)
    alone = ExpectedLoss().decide(0.05, evidence=good)
    assert alone.action == "pay" and "delivery_odds" not in alone.evidence
    doubtful = ExpectedLoss().decide(0.05, evidence=good, delivery_odds={"p": 0.6})
    assert abs(doubtful.posterior - 0.4) < 1e-9 and doubtful.action == "check_first"
    assert doubtful.evidence["delivery_odds"] == 0.6
    # Odds better than the posterior change nothing: the larger chance of loss stands.
    sure = ExpectedLoss().decide(0.05, delivery_odds={"p": 0.999})
    assert abs(sure.posterior - ExpectedLoss().decide(0.05).posterior) < 1e-12
    assert ExpectedLoss().decide(0.05, delivery_odds={"p": "x"}).posterior == ExpectedLoss().decide(0.05).posterior
