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

"""A buyer's policy for x402 payments: pay only for offers that show the proof you ask for.

Drop it in front of an x402 client. Before each payment it checks that the
402's price doesn't exceed the listing or the quote, that the seller meets the
buyer's proof tier (any, sampled or delivered), and that the offer carries no
text written to steer an agent. It sends an Accept-Proof header, keeps signed
receipts locally, and, only if the buyer opts in, reports anonymized proof
rules and unmet intents to Agoranome's two public indexes.

No dependencies beyond the standard library.
"""

__version__ = "0.1.0"

from agoranome_policy.offer import Offer, OfferError, Option, from_header, from_json, from_response  # noqa: E402
from agoranome_policy.policy import Choice, Decision, Policy  # noqa: E402
from agoranome_policy.proof import TIERS  # noqa: E402

__all__ = ["Choice", "Decision", "Offer", "OfferError", "Option", "Policy", "TIERS", "__version__",
           "from_header", "from_json", "from_response"]
