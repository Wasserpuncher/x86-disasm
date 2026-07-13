"""The test that actually matters: agree with GNU objdump, on real binaries.

Hand-written unit tests only cover the cases you thought of. The instructions
that break a decoder are the ones you didn't -- so point it at a few hundred
thousand instructions of real compiler output and let a known-correct
disassembler be the judge.

Two things are checked, and the first matters more:

  length   x86 instructions are variable-length. Get one length wrong and you
           resume decoding mid-instruction, and every byte after that is
           nonsense. A length mismatch is a hard failure.
  text     mnemonic and operands, normalised for whitespace.
"""

import os
import subprocess
import tempfile

import pytest

from x86disasm import reference
from x86disasm.decode import Decoder, Undecodable

pytestmark = pytest.mark.skipif(not reference.available(), reason="needs objdump")

CANDIDATES = [
    "/usr/bin/bash", "/bin/bash",
    "/usr/bin/objdump",
    "/usr/bin/git",
    "/usr/lib64/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6",
]
BINARIES = [p for p in CANDIDATES if os.path.exists(p)]
LIMIT = 200_000


def text_section(path: str) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        out = f.name
    subprocess.run(["objcopy", "-O", "binary", "--only-section=.text", path, out],
                   check=True, capture_output=True)
    data = open(out, "rb").read()
    os.unlink(out)
    return data


@pytest.mark.skipif(not BINARIES, reason="no system binaries found")
@pytest.mark.parametrize("path", BINARIES)
def test_agrees_with_objdump(path):
    code = text_section(path)[:LIMIT]
    if not code:
        pytest.skip(f"no .text in {path}")

    ref = [r for r in reference.objdump(code) if r.mnemonic != "(bad)"]
    assert ref, "objdump found nothing to compare against"

    decoded = 0
    length_errors, text_errors = [], []

    for r in ref:
        dec = Decoder(code, 0)
        dec.pos = r.addr
        try:
            ins = dec.decode_one()
        except (Undecodable, IndexError, KeyError):
            continue                       # an opcode we don't claim to support
        decoded += 1
        if ins.length != r.length:
            length_errors.append(f"{r.addr:#x} {r.raw.hex(' ')}: "
                                 f"us={ins.length} objdump={r.length} ({ins})")
        elif (reference.normalize(f"{ins.mnemonic} {ins.operands}")
              != reference.normalize(f"{r.mnemonic} {r.operands}")):
            theirs = f"{r.mnemonic} {r.operands}".strip()
            text_errors.append(f"{r.addr:#x} {r.raw.hex(' ')}: "
                               f"us={str(ins)!r} objdump={theirs!r}")

    assert not length_errors, (
        f"{len(length_errors)} instructions decoded to the wrong length -- the "
        f"decoder would lose sync:\n  " + "\n  ".join(length_errors[:10])
    )
    assert not text_errors, (
        f"{len(text_errors)} instructions disagree with objdump:\n  "
        + "\n  ".join(text_errors[:10])
    )
    # Anything below this and the "verified against objdump" claim is hollow.
    assert decoded / len(ref) > 0.90, (
        f"only decoded {decoded}/{len(ref)} ({decoded / len(ref) * 100:.1f}%)"
    )
