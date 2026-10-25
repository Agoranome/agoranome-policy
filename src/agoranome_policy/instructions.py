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

"""Text that reads as an instruction to a buyer agent rather than as data.

A planted sentence in a tool description can make an agent pick the
attacker's tool most of the time (ToolHijacker, NDSS 2026), and a paid
response can carry the same thing. These are the patterns the Bazaar screens
listings for and Agoranome's listing lint flags.
"""

import re
from typing import List

INSTRUCTION_PATTERNS = [
    r"\bignore (all|any|the|your|previous|prior|other)\b",
    r"\bdisregard\b",
    r"\b(always|must|should|you should) (choose|pick|select|prefer|call|use) (this|us|me|our)\b",
    r"\b(choose|pick|select|prefer) (this|us|me|our \w+) (over|instead|first|before)\b",
    r"\bdo not (choose|pick|select|use|call) (any|other|another|competing)\b",
    r"\bsystem prompt\b",
    r"\byou are (an?|the) (ai|assistant|agent|model|llm)\b",
    r"\b(attention|note to|dear) (ai|llm|agents?|assistants?|models?)\b",
    r"<\s*/?\s*(system|instructions?|prompt)\s*>",
    r"\[\s*/?\s*(system|inst)\s*\]",
]
_RE = re.compile("|".join(INSTRUCTION_PATTERNS), re.IGNORECASE)
MAX_SCAN_CHARS = 200_000


def instruction_like(text: str) -> List[str]:
    """Phrases in `text` that read as instructions to a buyer agent."""
    return sorted({m.group(0) for m in _RE.finditer((text or "")[:MAX_SCAN_CHARS])})
