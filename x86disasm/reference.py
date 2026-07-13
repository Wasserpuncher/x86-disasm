"""Runs GNU objdump over the same bytes, so the two can be compared.

objdump is the reference implementation here, the way `re` is the reference for
a hand-written regex engine: it is known-correct, so any disagreement is our
bug, not its.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

_LINE = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(.*)$")


@dataclass
class RefInsn:
    addr: int
    length: int
    mnemonic: str
    operands: str
    raw: bytes


def available() -> bool:
    return shutil.which("objdump") is not None


def objdump(code: bytes, base: int = 0) -> list[RefInsn]:
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(code)
        path = f.name

    out = subprocess.run(
        ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
         "-M", "intel", f"--adjust-vma={base:#x}", path],
        capture_output=True, text=True, check=True,
    ).stdout

    insns: list[RefInsn] = []
    for line in out.splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        addr, raw_hex, text = m.groups()
        raw = bytes.fromhex(raw_hex.replace(" ", ""))
        text = text.split("#")[0].strip()          # drop objdump's comments

        # objdump wraps instructions longer than 7 bytes onto a second line,
        # which carries only bytes and no mnemonic. That is a continuation of
        # the previous instruction, not a new one -- a movabs (10 bytes) would
        # otherwise look 7 bytes long and the byte count would never line up.
        if not text and insns:
            insns[-1].raw += raw
            insns[-1].length += len(raw)
            continue

        parts = text.split(None, 1)
        mnemonic = parts[0] if parts else ""
        operands = parts[1].strip() if len(parts) > 1 else ""
        insns.append(RefInsn(int(addr, 16), len(raw), mnemonic, operands, raw))
    return insns


def normalize(operands: str) -> str:
    """Squash the cosmetic differences so only real disagreements survive."""
    s = operands.split("#")[0]                     # objdump's target comments
    s = s.replace(" ", "").replace("PTR", " PTR ")
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s
