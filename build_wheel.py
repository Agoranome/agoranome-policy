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

"""Build the pack's wheel, byte-for-byte the same as the one agoranome.com/policy serves.

Fixed timestamps and a fixed file order make the bytes depend only on the
source, so anyone can rebuild the wheel and compare its sha256 with the
published one. Standard library only.

    python build_wheel.py [outdir]     # writes the wheel, prints its name and sha256
"""

import base64
import hashlib
import io
import re
import sys
import zipfile
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).resolve().parent
NAME = "agoranome_policy"
DIST = "agoranome-policy"
PACKAGE = ROOT / "src" / NAME
_EPOCH = (2026, 10, 25, 0, 0, 0)


def version() -> str:
    text = (PACKAGE / "__init__.py").read_text()
    return re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.M).group(1)


def wheel_name() -> str:
    return f"{NAME}-{version()}-py3-none-any.whl"


def _metadata() -> str:
    readme = (ROOT / "README.md").read_text()
    return "\n".join([
        "Metadata-Version: 2.1", f"Name: {DIST}", f"Version: {version()}",
        "Summary: A buyer's policy for x402 payments: pay only for offers that show the proof you ask for.",
        "Home-page: https://agoranome.com/policy", "License: Apache-2.0", "Requires-Python: >=3.9",
        "Classifier: License :: OSI Approved :: Apache Software License",
        "Classifier: Programming Language :: Python :: 3",
        "Description-Content-Type: text/markdown", "", readme])


def _record_line(path: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{path},sha256={digest},{len(data)}"


def _files() -> List[Tuple[str, bytes]]:
    files = [(f"{NAME}/{p.relative_to(PACKAGE).as_posix()}", p.read_bytes())
             for p in sorted(PACKAGE.rglob("*.py"))]
    info = f"{NAME}-{version()}.dist-info"
    files += [
        (f"{info}/METADATA", _metadata().encode()),
        (f"{info}/WHEEL", b"Wheel-Version: 1.0\nGenerator: agoranome\nRoot-Is-Purelib: true\nTag: py3-none-any\n"),
        (f"{info}/entry_points.txt", b"[console_scripts]\nagoranome-policy = agoranome_policy.cli:main\n"),
        (f"{info}/LICENSE", (ROOT / "LICENSE").read_bytes()),
    ]
    record = "\n".join([_record_line(p, d) for p, d in files] + [f"{info}/RECORD,,"]) + "\n"
    return files + [(f"{info}/RECORD", record.encode())]


def wheel() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, data in _files():
            entry = zipfile.ZipInfo(path, date_time=_EPOCH)
            entry.external_attr = 0o644 << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data)
    return buffer.getvalue()


def main() -> None:
    outdir = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    outdir.mkdir(parents=True, exist_ok=True)
    data = wheel()
    (outdir / wheel_name()).write_bytes(data)
    print(wheel_name(), hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    main()
