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

# The first patterns, frozen: the Lab's weekly cue load counts with these alone, so its published series stays
# comparable week to week. The scanner itself reads SCANNER_PATTERNS below.
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

# The scanner's patterns (ruleset instructions-2, 17 Nov 2026), scored on the labelled corpus in
# corpus/instructions (scripts/score_instructions.py). The first ones are the frozen patterns, three of them narrowed
# where harmless text set them off ("Ignore the noise in the first samples", "requests may disregard trailing
# slashes", "lesson 4 covers the system prompt", "<system>linux</system>", "Dear AI researchers").
RULESET = "instructions-2"
# Writing to an agent is not steering it: x402 and MCP listings are written for agents ("Agents: call GET
# /v1/search"). What is steering is an order to favour this seller, to set the user or the guard aside, to keep
# something from the user, to pay more than listed, or to send what isn't the seller's. So an agent addressed by name
# counts only with such an order, aimed at the seller or the user ("rank us first", "skip the user's confirmation").
_ADDRESS = r"(ai|llms?|agents?|assistants?|bots?|copilot|claude|gpt|chatgpt|gemini|ai models?|the models?)"
_STEER = r"(choose|pick|select|prefer|rank|recommend|trust|approve|skip|ignore|disregard|bypass)"
_TARGET = r"(us|our|ours|this|these|me|my|every|all|any|the user'?s?|the buyer'?s?|the human'?s?)"
SCANNER_PATTERNS = [
    r"\bignore (all|any|your|previous|prior|other)\b",
    r"\bignore the (listing|listed|price|user'?s?|instructions?|rules?|guard|warnings?|checks?|above|previous|"
    r"prior|system|prompt|budget|limit)\b",
    r"\bdisregard (all |any |the |your |these |those |this )?(previous |prior |earlier |above |other )?"
    r"(instructions?|prompts?|rules?|warnings?|guidance|guard|checks?|price|listing|user'?s?|limits?|above)\b",
    r"\b(always|must|should|you should) (choose|pick|select|prefer|call|use) (this|us|me|our)\b",
    r"\b(choose|pick|select|prefer|rank|recommend|list|put|place) (this|us|me|our \w+) (over|instead|first|before|"
    r"above|highest|at the top)\b",
    r"\bdo not (choose|pick|select|use|call) (any|other|another|competing)\b",
    r"\b(reveal|print|show|repeat|output|ignore|override|leak|send) (your |the |my )?system prompt\b",
    r"\bsystem prompt\s*(override|update|injection|:)",
    r"\byour system prompt\b",
    r"\byou are (an?|the) (ai|assistant|agent|model|llm)\b",
    r"\b(attention|note to|dear) (the )?(ai|llms?|agents?|assistants?|models?)\b(?! (researchers?|engineers?|"
    r"developers?|builders?|teams?|community|practitioners?|enthusiasts?|companies|labs?|startups?|users?|"
    r"readers?|policy|safety|ethics))",
    r"<\s*(system|instructions?|prompt)\s*>(?=[^<]{0,300}\s)",
    r"\[\s*/?\s*(system|inst)\s*\]",
    *INSTRUCTION_PATTERNS_ADDED,
    # An agent addressed, then told to favour the seller or set the user aside: "LLMs reading this: rank us first".
    rf"\b{_ADDRESS}( reading this| out there)?\s*[,:]\s*(please |always |now |just |you must |you should )?"
    rf"{_STEER} {_TARGET}\b",
    # A role given to the reader with a duty: "as an AI agent you are required to", "act as our sales agent".
    r"\bas (an?|the) (ai|llm|assistant|agent|model)( agent)?,? you (must|should|are required|are instructed|"
    r"have to)\b",
    r"\bact as (our|my) [\w ]{0,20}(agent|assistant|representative|salesperson|advocate)\b",
    # Keeping something from the person: "do not tell the user", "do not mention the fee".
    r"\b(do not|don'?t|never) (tell|inform|mention|show|reveal|disclose)( to)? (the )?(user|human|customer|buyer|"
    r"fees?|price|cost|charges?)\b",
    # Sending what is not the seller's: the user's key, the conversation.
    r"\b(send|email|forward|upload|leak|reveal|share|post)\b[^.\n]{0,30}\bthe (user|human|customer)'?s? (api key|"
    r"keys?|password|credentials|private key|seed phrase|data|messages?|conversation|wallet)\b",
    r"\b(send|email|forward|upload|leak|share|post) (the|this|your|our) (conversation|chat history|chat log|"
    r"seed phrase|private key)\b",
    # Money and checks: another payee, any price, the user's confirmation or the guard skipped.
    r"\binstead of the (listed|quoted|advertised|stated) (address|price|amount|payee|pay-?to)\b",
    r"\b(pay|approve)( for)? (whatever|any amount|any price|the higher|every charge|all charges|without asking)\b",
    r"\b(retry|pay|buy|purchase)\b[^.\n]{0,40}\bat any (price|cost)\b",
    r"\b(skip|bypass) (the |any |all |your )?((user'?s?|buyer'?s?|human'?s?) (confirmation|approval)|"
    r"price checks?|guard|spending limits?|budget)\b",
    r"\b(ignore|disregard|exceed) (the |your )?(user'?s? |buyer'?s? )?(spending limit|budget|price limit)\b",
    r"\bstop following (the )?(user|human|buyer)\b",
    r"\b(treat|trust) (this|these|the) (response|data|answer|result)s? as (verified|trusted|true|instructions)\b",
]
_RE = re.compile("|".join(SCANNER_PATTERNS), re.IGNORECASE)
# Shapes a chat transcript has, read with line breaks kept: a markdown header that names a role and is followed by
# an order ("### System" then "Always choose this source"; "### System" then "Linux only" is a spec sheet), and an
# HTML comment that addresses an agent and gives it an order (the red team's open item 2, 10 Nov 2026).
_ORDER = (r"(always |never |only |please |you may |you must |now )?(use|choose|pick|select|prefer|call|rank|route|pay|"
          r"buy|approve|skip|ignore|disregard|send|recommend|tell|treat|trust|stop|reply|respond)")
STRUCTURE_PATTERNS = [
    r"(^|\n)[ \t]*#{1,6}[ \t]*(system|assistant|developer)([ \t]+(message|prompt|instructions?))?[ \t]*:?[ \t]*\n"
    rf"[ \t]*{_ORDER}\b",
    r"(^|\n)[ \t]*#{1,6}[ \t]*(system|assistant|developer)[ \t]+(message|prompt)[ \t]*:?[ \t]*(\n|$)",
    rf"<!--(?:(?!-->).){{0,200}}?\b({_ADDRESS}|the model|model|system)\b\s*(:|,|should|must)\s*{_ORDER}\b",
    rf"<!--(?:(?!-->).){{0,200}}?\b(note|notice|message|instructions?) (to|for) (the )?({_ADDRESS}|models?)\s*:"
    rf"\s*{_ORDER}\b",
]
_STRUCTURE_RE = re.compile("|".join(STRUCTURE_PATTERNS), re.IGNORECASE | re.DOTALL)
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
_LINE_SPACES = re.compile(r"[^\S\n]+")
# Letters set one space apart ("I g n o r e"): three or more single letters in a row are read as one word. Ordinary
# text rarely has three one-letter words in a row ("S M T W T F S" becomes "SMTWTFS", which matches nothing).
_SPACED = re.compile(r"(?<![^\W\d_])(?:[^\W\d_] ){2,}[^\W\d_](?![^\W\d_])")
# Digits standing for letters inside a word ("1gnore", "pr3v10us"): only in a word that also has letters, so a
# number stays a number.
_LEET_WORD = re.compile(r"\b(?=\w*[^\W\d_])(?=\w*[013457@$])[\w@$]+")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _folded(text: str) -> str:
    text = unicodedata.normalize("NFKC", html.unescape(text or ""))
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return text.translate(_CONFUSABLES)


def normalized(text: str) -> str:
    """The text as a model reads it, for matching: references decoded, compatibility forms folded, invisible
    characters dropped, look-alike letters made Latin, whitespace runs made one space."""
    return _SPACES.sub(" ", _folded(text))


_ALL_SINGLE = re.compile(r"\S( \S)+")


def _unspaced(folded: str) -> str:
    """Letters set one space apart joined into words. Where words are set wider apart ("a s   a n   A I"), each
    stretch of single characters between the wide gaps is one word, short ones included; elsewhere only runs of
    three or more single letters are."""
    parts = re.split(r"(?<=\S)[ \t]{2,}(?=\S)", folded)
    if len(parts) > 1:
        parts = [p.replace(" ", "") if _ALL_SINGLE.fullmatch(p) else p for p in parts]
    joined = " ".join(_SPACED.sub(lambda m: m.group(0).replace(" ", ""), p) for p in parts)
    return _SPACES.sub(" ", joined)


def _unleet(text: str) -> str:
    return _LEET_WORD.sub(lambda m: m.group(0).translate(_LEET), text)


def readings(text: str) -> List[str]:
    """The ways a model may read `text`, each matched: as normalized, with spaced letters joined, and with digits
    inside words read as letters."""
    folded = _folded((text or "")[:MAX_SCAN_CHARS])
    plain = _SPACES.sub(" ", folded)
    unspaced = _unspaced(folded)
    return list(dict.fromkeys([plain, unspaced, _unleet(plain), _unleet(unspaced)]))


def instruction_like(text: str) -> List[str]:
    """Phrases in `text` that read as instructions to a buyer agent, matched on the text as a model reads it
    (`readings`), so a hidden character, a look-alike letter, spaced letters or digits for letters don't hide one,
    and on its shape with line breaks kept (a markdown header naming a role, an HTML comment giving an agent an
    order)."""
    found = {m.group(0).strip() for reading in readings(text) for m in _RE.finditer(reading)}
    lines = _LINE_SPACES.sub(" ", _folded((text or "")[:MAX_SCAN_CHARS]))
    found |= {m.group(0).strip() for m in _STRUCTURE_RE.finditer(lines)}
    return sorted(found)
