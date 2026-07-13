"""CLI: disassemble a file, or check ourselves against objdump."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile

from .decode import Decoder, Undecodable, disassemble
from . import reference


def _section(path: str, name: str = ".text") -> bytes:
    """Pull one section out of an ELF file, with objcopy."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        out = f.name
    subprocess.run(["objcopy", "-O", "binary", f"--only-section={name}", path, out],
                   check=True, capture_output=True)
    return open(out, "rb").read()


def cmd_dump(args) -> int:
    code = _section(args.file) if args.section else open(args.file, "rb").read()
    if args.limit:
        code = code[:args.limit]
    for ins in disassemble(code, args.base):
        target = f"   # {ins.rip_target:x}" if ins.rip_target is not None else ""
        print(f"{ins.addr:08x}  {ins.raw.hex(' '):<30}  {ins}{target}")
    return 0


def cmd_verify(args) -> int:
    """Decode a binary and compare every instruction against GNU objdump.

    This is the whole point of the project, so it is a command and not just a
    test: run it on anything on your machine and see whether we disagree.
    """
    if not reference.available():
        print("objdump not found -- install binutils", file=sys.stderr)
        return 2

    code = _section(args.file)[:args.limit]
    ref = reference.objdump(code)
    real = [r for r in ref if r.mnemonic != "(bad)"]

    known = wrong_len = wrong_text = 0
    for r in real:
        dec = Decoder(code, 0)
        dec.pos = r.addr
        try:
            ins = dec.decode_one()
        except (Undecodable, IndexError, KeyError):
            continue
        known += 1
        if ins.length != r.length:
            wrong_len += 1
            print(f"  LENGTH {r.addr:#08x} {r.raw.hex(' '):<24} "
                  f"us={ins.length} objdump={r.length}")
        elif (reference.normalize(f"{ins.mnemonic} {ins.operands}")
              != reference.normalize(f"{r.mnemonic} {r.operands}")):
            wrong_text += 1
            print(f"  TEXT   {r.addr:#08x} {r.raw.hex(' '):<24}\n"
                  f"         us:      {ins}\n         objdump: {r.mnemonic} {r.operands}")

    exact = known - wrong_len - wrong_text
    print(f"\n{args.file}")
    print(f"  instructions:   {len(real):,}")
    print(f"  decoded:        {known:,}  ({known / len(real) * 100:.1f}%)")
    print(f"  wrong length:   {wrong_len}")
    print(f"  wrong text:     {wrong_text}")
    print(f"  exact:          {exact:,}  ({exact / known * 100:.4f}%)")
    return 1 if (wrong_len or wrong_text) else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="x86disasm", description="An x86-64 disassembler.")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("dump", help="disassemble a file")
    d.add_argument("file")
    d.add_argument("--section", action="store_true", help="pull .text out of an ELF first")
    d.add_argument("--base", type=lambda s: int(s, 0), default=0)
    d.add_argument("--limit", type=int, default=0)
    d.set_defaults(func=cmd_dump)

    v = sub.add_parser("verify", help="compare our output against GNU objdump")
    v.add_argument("file", help="an ELF binary, e.g. /usr/bin/git")
    v.add_argument("--limit", type=int, default=300_000, help="bytes of .text to check")
    v.set_defaults(func=cmd_verify)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
