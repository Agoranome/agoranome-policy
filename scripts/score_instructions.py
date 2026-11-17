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

"""The instruction scanner's score on the labelled corpus: how many planted instructions it catches and how many
harmless texts it flags, by family and by split, each with a 95% Wilson interval.

  python scripts/score_instructions.py                        # this repo's scanner
  python scripts/score_instructions.py --scanner PATH.py      # any copy (fair-meter's, the Lab's)
  python scripts/score_instructions.py --show                 # and every miss and false alarm
  python scripts/score_instructions.py --json                 # the figures as JSON

A scanner is any Python file with instruction_like(text) -> list of matched phrases.
"""

import argparse
import importlib.util
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus" / "instructions" / "corpus.jsonl"
HOME = ROOT / "src" / "agoranome_policy" / "instructions.py"


def wilson(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    if not n:
        return 0.0, 1.0
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def load_scanner(path: Path) -> Callable[[str], List[str]]:
    spec = importlib.util.spec_from_file_location(f"scanner_{abs(hash(str(path)))}", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module.instruction_like


def read_corpus(path: Path = CORPUS) -> List[Dict[str, str]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def score(scan: Callable[[str], List[str]], corpus: List[Dict[str, str]]) -> Dict[str, Any]:
    """{"planted": {...}, "harmless": {...}, "families": {...}, "misses": [...], "false_alarms": [...]}"""
    cells: Dict[Tuple[str, str], List[int]] = defaultdict(lambda: [0, 0])
    families: Dict[Tuple[str, str], List[int]] = defaultdict(lambda: [0, 0])
    misses, false_alarms = [], []
    for row in corpus:
        flagged = bool(scan(row["text"]))
        for split in (row["split"], "all"):
            cell = cells[(row["label"], split)]
            cell[0] += flagged
            cell[1] += 1
        fam = families[(row["label"], row["family"])]
        fam[0] += flagged
        fam[1] += 1
        if row["label"] == "planted" and not flagged:
            misses.append(row)
        if row["label"] == "harmless" and flagged:
            false_alarms.append({**row, "matched": scan(row["text"])})

    def figure(k: int, n: int) -> Dict[str, Any]:
        low, high = wilson(k, n)
        return {"flagged": k, "of": n, "rate": round(k / n, 3) if n else None,
                "interval": [round(low, 3), round(high, 3)]}

    return {
        "planted": {split: figure(*cells[("planted", split)]) for split in ("dev", "held_out", "all")},
        "harmless": {split: figure(*cells[("harmless", split)]) for split in ("dev", "held_out", "all")},
        "families": {f"{label}/{family}": figure(*v) for (label, family), v in sorted(families.items())},
        "misses": misses,
        "false_alarms": false_alarms,
    }


def _pct(fig: Dict[str, Any]) -> str:
    low, high = fig["interval"]
    share = f"{100 * fig['rate']:5.1f}%"
    return f"{fig['flagged']:>3} of {fig['of']:>3} ({share}, 95% CI {100 * low:.0f} to {100 * high:.0f}%)"


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--scanner", type=Path, default=HOME)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--show", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = score(load_scanner(args.scanner), read_corpus(args.corpus))
    if args.json:
        print(json.dumps({k: v for k, v in result.items() if k not in ("misses", "false_alarms")}, indent=2))
        return 0
    print(f"scanner: {args.scanner}")
    for split in ("dev", "held_out", "all"):
        print(f"caught    {split:<9} {_pct(result['planted'][split])}")
    for split in ("dev", "held_out", "all"):
        print(f"false alarm {split:<7} {_pct(result['harmless'][split])}")
    print("by family:")
    for name, fig in result["families"].items():
        print(f"  {name:<34} {_pct(fig)}")
    if args.show:
        for row in result["misses"]:
            print(f"MISS  {row['id']:<22} {row['text'][:100]!r}")
        for row in result["false_alarms"]:
            print(f"FALSE {row['id']:<22} {row['text'][:80]!r} -> {row['matched']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
