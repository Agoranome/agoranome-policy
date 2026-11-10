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

import html
import re
import unicodedata
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
INSTRUCTION_PATTERNS_ADDED = [
    r"\bforget (all |any |the |your )?(previous|prior|earlier|above|preceding|other) (instructions?|prompts?|rules?|messages?)\b",
    r"\boverride (all |any |your )(previous |prior |other )?(instructions?|rules?|system prompt)\b",
    r"\bnew instructions?\s*:",
    r"<\|\s*(im_start|im_end|system|assistant|endoftext)\s*\|>",
    r"\bthe only (tool|service|api|option|seller) (you|agents?|models?) (should|must|may) (call|use|pick|choose|select)\b",
]
_RE = re.compile("|".join(INSTRUCTION_PATTERNS + INSTRUCTION_PATTERNS_ADDED), re.IGNORECASE)
MAX_SCAN_CHARS = 200_000

# Text a model still reads where a person's eye or a plain regex would miss it: HTML character references, compatibility forms
# (fullwidth letters), invisible format characters (zero-width, soft hyphen, bidi controls, tag characters), Cyrillic
# and Greek letters that look Latin, and any run of whitespace. The patterns are matched on the text so normalized.
_CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0443": "y", "\u0445": "x",
    "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u0501": "d", "\u04bb": "h", "\u0410": "A", "\u0412": "B",
    "\u0415": "E", "\u041a": "K", "\u041c": "M", "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C",
    "\u0422": "T", "\u0425": "X", "\u0406": "I", "\u0408": "J", "\u0405": "S", "\u03bf": "o", "\u039f": "O",
    "\u03b1": "a", "\u03b9": "i", "\u0399": "I", "\u03bd": "v", "\u03c1": "p", "\u0391": "A", "\u0392": "B",
    "\u0395": "E", "\u0397": "H", "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u03a4": "T", "\u03a7": "X",
    "\u03a5": "Y", "\u0396": "Z",
})
_SPACES = re.compile(r"\s+")


def normalized(text: str) -> str:
    """The text as a model reads it, for matching: references decoded, compatibility forms folded, invisible
    characters dropped, look-alike letters made Latin, whitespace runs made one space."""
    text = unicodedata.normalize("NFKC", html.unescape(text or ""))
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return _SPACES.sub(" ", text.translate(_CONFUSABLES))


def instruction_like(text: str) -> List[str]:
    """Phrases in `text` that read as instructions to a buyer agent, matched on the text as a model reads it
    (`normalized`), so a hidden character or a look-alike letter doesn't hide one."""
    return sorted({m.group(0) for m in _RE.finditer(normalized((text or "")[:MAX_SCAN_CHARS]))})
