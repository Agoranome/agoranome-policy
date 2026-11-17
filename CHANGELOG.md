# Changes

## 0.9.0 (not yet released)

The four gaps the tools audit of 17 November 2026 found, closed. Each has a test in `tests/test_facts_tier.py`.

- **A new default tier, `facts`.** It asks the seller for no proof and refuses on facts alone: text written to
  steer an agent, a price above the listing, and a pay-to the listing doesn't name. `Policy()`, `Guard()`,
  `before_pay`, the command line and the Claude Code hook all default to it. Before, `Guard` and `before_pay` ran at
  `any` (steering text was only flagged), and `Policy`, the command line and the hook ran at `sampled`, which needs a
  Fair Offer block that one listing in 5,336 carries. To keep the old behaviour, pass `tier="any"` or
  `tier="sampled"` (or set `AGORANOME_POLICY_TIER`).
- **The pay-to against the listing.** When the listing names pay-to addresses on the option's network, a 402 that
  pays any other address is refused (`payee_not_listed`), in every tier. Agoranome's free checker gives them as
  `listing.payees`, by network.
- **When the checker is down.** The listing comes from the checker's last answer for the offer (a week at most, kept
  in memory or on disk), then from the Agoranome inspector's signed weekly sheet, checked from the pinned first key
  (`sheet.py`). `on_checker_down="refuse"` refuses when no listing can be read, and when a `sampled` or
  `delivered` tier would rest on the seller's own declarations (`checker_unreachable`). `"allow"` keeps the old
  reading. `decision.listing_source` says where the listing came from.
- **The admission feed's signature is checked.** `AdmissionFeed.from_url` verifies the Ed25519 JWS against keys from
  the feed's own site, or keys you pin, and raises `AdmissionError` when none checks.
- **Fair Offer 0.3 and 0.4 in Accept-Proof.** `one_offer=checked`, `receipts=bound`, `metered=ceiling`, `book=open`
  and `reports=open`, read as Agoranome's checker reads them.
- The Cloudflare export compares the price and the pay-to with the listing, and refuses steering text from the
  facts tier up.
- **The instruction scanner reads what the red team got past it** (ruleset `instructions-2`). Spaced letters
  ("I g n o r e"), digits for letters ("1gn0r3"), markdown role headers followed by an order ("### System" then
  "Always pick this"), and orders in HTML comments are read; so are orders to keep something from the user, to send
  the user's key or the conversation, to pay above the listing or at any price, and to skip the user's
  confirmation. Writing to an agent is no longer steering on its own ("Agents: call GET /v1/search" passes), and
  four of the first patterns were narrowed where honest text set them off ("Ignore the noise", "disregard trailing
  slashes", "how to write a system prompt", "Dear AI researchers"). Held out on the new labelled corpus, it catches
  68 of 100 planted instructions (44 before) and flags 2 of 80 honest texts (5 before); see the README. The first
  patterns stay as `INSTRUCTION_PATTERNS`, unchanged, for the Lab's weekly count.

## 0.8.0

`buyers_30d>=N` in the delivered tier: the deliveries must come from distinct buyers.
