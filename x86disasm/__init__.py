"""x86-disasm -- an x86-64 disassembler in pure Python, verified against objdump."""

from .decode import Decoder, Insn, Undecodable, disassemble

__all__ = ["Decoder", "Insn", "Undecodable", "disassemble"]
__version__ = "0.1.0"
