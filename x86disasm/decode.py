"""An x86-64 instruction decoder.

x86 instructions have no fixed length. You cannot know where the next one
starts until you have fully decoded this one, and decoding means walking a
little state machine:

    [prefixes] [REX] opcode [ModRM] [SIB] [displacement] [immediate]

Every part is optional and every part changes how the next part is read. REX.W
turns a 32-bit operation into a 64-bit one; REX.B extends a register number
from 3 bits to 4; a ModRM byte of mod=00 rm=101 does not mean "[rbp]", it means
"RIP-relative, and there are four more bytes of displacement". Get one of those
wrong and you don't just misprint an operand -- you resume decoding at the
wrong byte and everything after it is garbage.

That is why the test suite checks instruction *lengths* against GNU objdump as
carefully as it checks mnemonics: a length that is off by one is a decoder that
has silently lost the plot.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

REGS64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
REGS32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
          "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"]
REGS8 = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
         "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"]
REGS8_NOREX = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"]

# ModRM.reg selects the operation for these opcodes rather than a register.
GROUP1 = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
GROUP3 = ["test", "test", "not", "neg", "mul", "imul", "div", "idiv"]
GROUP5 = ["inc", "dec", "call", "callf", "jmp", "jmpf", "push", None]
SHIFT = ["rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"]

CONDITIONS = ["o", "no", "b", "ae", "e", "ne", "be", "a",
              "s", "ns", "p", "np", "l", "ge", "le", "g"]

PTR = {8: "BYTE PTR", 16: "WORD PTR", 32: "DWORD PTR", 64: "QWORD PTR"}


class Undecodable(Exception):
    """These bytes are not an instruction we know."""


@dataclass
class Insn:
    addr: int
    length: int
    mnemonic: str
    operands: str
    raw: bytes
    rip_target: int | None = None    # resolved address, for RIP-relative operands

    def __str__(self) -> str:
        return f"{self.mnemonic} {self.operands}".strip()


def _hex(v: int) -> str:
    """objdump prints negatives as -0x8, not as 0xfffffff8."""
    return f"-0x{-v:x}" if v < 0 else f"0x{v:x}"


def _target(v: int) -> str:
    """A branch target is an address, so it wraps into 64 bits rather than
    going negative -- objdump prints 0xfffffffffffff2b0, not -0xd50."""
    return f"0x{v & 0xFFFF_FFFF_FFFF_FFFF:x}"


_MASK = {8: 0xFF, 16: 0xFFFF, 32: 0xFFFF_FFFF, 64: 0xFFFF_FFFF_FFFF_FFFF}


def _imm(v: int, size: int) -> str:
    """An immediate is a bit pattern, not a number with a sign.

    `and rsp, -0x10` and `and rsp, 0xfffffffffffffff0` are the same 64 bits;
    objdump prints the second, because that is what the CPU sees. Sign-extended
    imm8s therefore have to be widened to the operand size first.
    """
    return f"0x{v & _MASK[size]:x}"


class Decoder:
    def __init__(self, code: bytes, base: int = 0):
        self.code = code
        self.base = base
        self.pos = 0
        # per-instruction state
        self.rex = 0
        self.has_rex = False      # 0x40 is a REX with no bits set -- still a REX
        self.seg = None
        self.opsize = 32

    # -- byte reader -----------------------------------------------------

    def _u8(self) -> int:
        if self.pos >= len(self.code):
            raise Undecodable("ran off the end")
        b = self.code[self.pos]
        self.pos += 1
        return b

    def _i8(self) -> int:
        return struct.unpack("<b", bytes([self._u8()]))[0]

    def _i32(self) -> int:
        if self.pos + 4 > len(self.code):
            raise Undecodable("truncated dword")
        v = struct.unpack_from("<i", self.code, self.pos)[0]
        self.pos += 4
        return v

    def _u32(self) -> int:
        if self.pos + 4 > len(self.code):
            raise Undecodable("truncated dword")
        v = struct.unpack_from("<I", self.code, self.pos)[0]
        self.pos += 4
        return v

    def _i64(self) -> int:
        if self.pos + 8 > len(self.code):
            raise Undecodable("truncated qword")
        v = struct.unpack_from("<q", self.code, self.pos)[0]
        self.pos += 8
        return v

    def _i16(self) -> int:
        if self.pos + 2 > len(self.code):
            raise Undecodable("truncated word")
        v = struct.unpack_from("<h", self.code, self.pos)[0]
        self.pos += 2
        return v

    # -- registers -------------------------------------------------------

    def _reg(self, num: int, size: int | None = None) -> str:
        size = size or self.opsize
        if size == 64:
            return REGS64[num]
        if size == 32:
            return REGS32[num]
        if size == 16:
            return REGS32[num].replace("e", "", 1) if num < 8 else f"r{num}w"
        # 8-bit is where a bare 0x40 REX matters: with any REX present, regs 4-7
        # are spl/bpl/sil/dil; without one they are ah/ch/dh/bh. Testing the REX
        # *bits* misses this, because 0x40 has none set -- test its presence.
        if self.has_rex:
            return REGS8[num]
        return REGS8_NOREX[num] if num < 8 else REGS8[num]

    # -- ModRM / SIB -----------------------------------------------------

    def _modrm(self, size: int | None = None) -> tuple[int, str]:
        """Returns (reg field, rendered r/m operand)."""
        size = size or self.opsize
        byte = self._u8()
        mod, reg, rm = byte >> 6, (byte >> 3) & 7, byte & 7
        reg |= (self.rex & 0b0100) << 1          # REX.R
        rm_ext = rm | ((self.rex & 0b0001) << 3)  # REX.B

        if mod == 0b11:
            return reg, self._reg(rm_ext, size)

        # rm == 100 means a SIB byte follows.
        if rm == 0b100:
            base, index, scale = self._sib(mod)
        else:
            index = scale = None
            if mod == 0b00 and rm == 0b101:
                # Not [rbp]. mod=00 rm=101 is the one encoding that means
                # RIP-relative, with a disp32 following. Reading it as a plain
                # [rbp] would both misname the operand and eat four bytes too few.
                self._rip_rel = self._i32()
                return reg, f"{PTR[size]} [rip]"     # patched in decode_one()
            base = self._reg(rm_ext, 64)

        disp = 0
        explicit_disp = False
        if mod == 0b01:
            disp, explicit_disp = self._i8(), True
        elif mod == 0b10:
            disp, explicit_disp = self._i32(), True
        elif mod == 0b00 and base is None:
            disp, explicit_disp = self._i32(), True

        parts = []
        if base:
            parts.append(base)
        if index:
            parts.append(f"{index}*{scale}")   # objdump prints the scale even when it is 1

        if not parts:
            # No base, no index: an absolute address. objdump renders it against
            # a segment -- ds by default, or whichever prefix was present -- and
            # an address is unsigned.
            return reg, f"{PTR[size]} {self.seg or 'ds'}:{_target(disp)}"

        addr = "+".join(parts)
        # A disp8 of zero is still encoded, and objdump shows it (`[r13+0x0]`).
        # Only mod=00 has no displacement byte at all.
        if explicit_disp or disp:
            addr += f"-0x{-disp:x}" if disp < 0 else f"+0x{disp:x}"
        prefix = f"{self.seg}:" if self.seg else ""
        return reg, f"{PTR[size]} {prefix}[{addr}]"

    def _sib(self, mod: int) -> tuple[str | None, str | None, int]:
        byte = self._u8()
        scale, index, base = 1 << (byte >> 6), (byte >> 3) & 7, byte & 7
        index |= (self.rex & 0b0010) << 2         # REX.X
        base_ext = base | ((self.rex & 0b0001) << 3)

        # index == 100 (and no REX.X) means "no index register".
        index_name = None if index == 0b100 else REGS64[index]
        # base == 101 with mod == 00 means "no base, disp32 instead".
        base_name = None if (base == 0b101 and mod == 0b00) else REGS64[base_ext]
        return base_name, index_name, scale

    # -- the instruction table -------------------------------------------

    # In long mode only fs and gs still relocate an address; cs/ds/es/ss are
    # ignored under flat memory. So the first two belong in the operand, and
    # the rest are dead prefixes that objdump prints as separate words.
    EFFECTIVE_SEG = {0x64: "fs", 0x65: "gs"}
    IGNORED_SEG = {0x2E: "cs", 0x36: "ss", 0x3E: "ds", 0x26: "es"}

    def decode_one(self) -> Insn:
        start = self.pos
        self.rex = 0
        self.has_rex = False
        self.seg = None
        self.dead_seg = None
        self.lock = False
        self.opsize = 32
        self._rip_rel = None

        n66 = 0
        while True:
            b = self.code[self.pos] if self.pos < len(self.code) else None
            if b == 0x66:
                self.opsize = 16
                n66 += 1
                self.pos += 1
            elif b in self.EFFECTIVE_SEG:
                # `mov rax, QWORD PTR fs:0x28` is the stack canary. Dropping
                # the segment loses what the instruction actually touches.
                self.seg = self.EFFECTIVE_SEG[b]
                self.pos += 1
            elif b in self.IGNORED_SEG:
                self.dead_seg = self.IGNORED_SEG[b]
                self.pos += 1
            elif b == 0xF0:
                # LOCK is not cosmetic: `lock sub` is atomic, `sub` is not.
                # Swallowing it turns a thread-safe instruction into a racy one
                # in the listing.
                self.lock = True
                self.pos += 1
            elif b in (0x67, 0xF2, 0xF3):
                self.pos += 1                      # accepted, not modelled
            else:
                break

        b = self._u8()
        if 0x40 <= b <= 0x4F:                      # REX
            self.rex = b & 0x0F
            self.has_rex = True
            if self.rex & 0b1000:                  # REX.W -> 64-bit operands
                self.opsize = 64
            b = self._u8()

        mnem, ops = self._opcode(b)

        # Dead prefixes get printed as words in front of the mnemonic. This is
        # almost entirely the multi-byte nop padding a compiler inserts between
        # functions (`data16 cs nop WORD PTR [rax+rax*1+0x0]`), plus CET's
        # `notrack` hint, which reuses the ds prefix on an indirect branch.
        words = []
        if self.lock:
            words.append("lock")
        if n66 > 1:
            words.append("data16")
        if self.dead_seg == "ds" and mnem in ("jmp", "call"):
            words.append("notrack")
        elif self.dead_seg:
            words.append(self.dead_seg)
        if words:
            mnem = " ".join(words + [mnem])

        length = self.pos - start

        if self._rip_rel is not None:
            ops = ops.replace("[rip]", f"[rip+{_target(self._rip_rel)}]")

        insn = Insn(self.base + start, length, mnem, ops,
                    bytes(self.code[start:self.pos]))
        if self._rip_rel is not None:
            # RIP is the address of the *next* instruction, so the target is
            # only knowable once the whole instruction has been measured.
            insn.rip_target = (self.base + start + length + self._rip_rel) & 0xFFFF_FFFF_FFFF_FFFF
        return insn

    def _opcode(self, b: int) -> tuple[str, str]:
        rexb = (self.rex & 0b0001) << 3

        # push/pop r64 -- default to 64-bit operand size, no REX.W needed
        if 0x50 <= b <= 0x57:
            return "push", REGS64[(b - 0x50) | rexb]
        if 0x58 <= b <= 0x5F:
            return "pop", REGS64[(b - 0x58) | rexb]

        # ALU: op r/m, r  and  op r, r/m
        for base_op, name in ((0x00, "add"), (0x08, "or"), (0x10, "adc"), (0x18, "sbb"),
                              (0x20, "and"), (0x28, "sub"), (0x30, "xor"), (0x38, "cmp")):
            if b == base_op + 0x00:               # r/m8, r8
                reg, rm = self._modrm(8)
                return name, f"{rm},{self._reg(reg, 8)}"
            if b == base_op + 0x01:               # r/m, r
                reg, rm = self._modrm()
                return name, f"{rm},{self._reg(reg)}"
            if b == base_op + 0x02:               # r8, r/m8
                reg, rm = self._modrm(8)
                return name, f"{self._reg(reg, 8)},{rm}"
            if b == base_op + 0x03:               # r, r/m
                reg, rm = self._modrm()
                return name, f"{self._reg(reg)},{rm}"
            if b == base_op + 0x04:               # al, imm8
                return name, f"al,{_imm(self._i8(), 8)}"
            if b == base_op + 0x05:               # eAX, imm
                # The immediate follows the operand size: a 0x66 prefix makes
                # this a 2-byte immediate, not 4. Reading 4 anyway swallows the
                # next instruction's first bytes and desynchronises everything
                # after it.
                imm = self._i16() if self.opsize == 16 else self._i32()
                return name, f"{self._reg(0)},{_imm(imm, self.opsize)}"

        if b == 0x80:                             # group1 r/m8, imm8
            reg, rm = self._modrm(8)
            return GROUP1[reg & 7], f"{rm},{_imm(self._i8(), 8)}"
        if b == 0x81:                             # group1 r/m, imm
            reg, rm = self._modrm()
            imm = self._i16() if self.opsize == 16 else self._i32()
            return GROUP1[reg & 7], f"{rm},{_imm(imm, self.opsize)}"
        if b == 0x83:                             # group1 r/m, imm8 sign-extended
            reg, rm = self._modrm()
            return GROUP1[reg & 7], f"{rm},{_imm(self._i8(), self.opsize)}"

        if b == 0x84:
            reg, rm = self._modrm(8)
            return "test", f"{rm},{self._reg(reg, 8)}"
        if b == 0x85:
            reg, rm = self._modrm()
            return "test", f"{rm},{self._reg(reg)}"

        if b == 0x88:
            reg, rm = self._modrm(8)
            return "mov", f"{rm},{self._reg(reg, 8)}"
        if b == 0x89:
            reg, rm = self._modrm()
            return "mov", f"{rm},{self._reg(reg)}"
        if b == 0x8A:
            reg, rm = self._modrm(8)
            return "mov", f"{self._reg(reg, 8)},{rm}"
        if b == 0x8B:
            reg, rm = self._modrm()
            return "mov", f"{self._reg(reg)},{rm}"
        if b == 0x8D:
            reg, rm = self._modrm()
            return "lea", f"{self._reg(reg)},{rm.split(' PTR ')[-1]}"

        if 0x90 <= b <= 0x97:
            # 0x90 is only a nop because it encodes `xchg eax, eax`. Add REX.B
            # and it swaps a different register; add 0x66 and it is `xchg ax,ax`.
            r = (b - 0x90) | rexb
            if r == 0 and self.opsize == 32:
                return "nop", ""
            return "xchg", f"{self._reg(r)},{self._reg(0)}"
        if b == 0x98:
            return {16: "cbw", 32: "cwde", 64: "cdqe"}[self.opsize], ""
        if b == 0x99:
            return {16: "cwd", 32: "cdq", 64: "cqo"}[self.opsize], ""

        if 0xB8 <= b <= 0xBF:                     # mov r, imm
            r = (b - 0xB8) | rexb
            if self.opsize == 64:                 # REX.W -> movabs with imm64
                return "movabs", f"{REGS64[r]},{_imm(self._i64(), 64)}"
            if self.opsize == 16:
                return "mov", f"{self._reg(r)},{_imm(self._i16(), 16)}"
            return "mov", f"{self._reg(r)},{_imm(self._u32(), 32)}"

        if b == 0xA8:                             # test al, imm8
            return "test", f"al,{_imm(self._u8(), 8)}"
        if b == 0xA9:                             # test eAX, imm
            imm = self._i16() if self.opsize == 16 else self._i32()
            return "test", f"{self._reg(0)},{_imm(imm, self.opsize)}"
        if 0xB0 <= b <= 0xB7:                     # mov r8, imm8
            return "mov", f"{self._reg((b - 0xB0) | rexb, 8)},{_hex(self._u8())}"

        if b in (0xC0, 0xC1, 0xD0, 0xD1, 0xD3):   # shifts
            size = 8 if b in (0xC0, 0xD0) else None
            reg, rm = self._modrm(size)
            name = SHIFT[reg & 7]
            if b in (0xC0, 0xC1):
                return name, f"{rm},{_hex(self._u8())}"
            if b in (0xD0, 0xD1):
                return name, f"{rm},1"
            return name, f"{rm},cl"

        if b == 0xC3:
            return "ret", ""
        if b == 0xC9:
            return "leave", ""
        if b == 0xCC:
            return "int3", ""

        if b == 0xC6:
            reg, rm = self._modrm(8)
            return "mov", f"{rm},{_imm(self._u8(), 8)}"
        if b == 0xC7:
            reg, rm = self._modrm()
            imm = self._i16() if self.opsize == 16 else self._i32()
            return "mov", f"{rm},{_imm(imm, self.opsize)}"

        if b == 0xE8:                             # call rel32
            rel = self._i32()
            return "call", _target(self.base + self.pos + rel)
        if b == 0xE9:                             # jmp rel32
            rel = self._i32()
            return "jmp", _target(self.base + self.pos + rel)
        if b == 0xEB:                             # jmp rel8
            rel = self._i8()
            return "jmp", _target(self.base + self.pos + rel)
        if 0x70 <= b <= 0x7F:                     # jcc rel8
            rel = self._i8()
            return "j" + CONDITIONS[b - 0x70], _target(self.base + self.pos + rel)

        if b == 0xF7:
            reg, rm = self._modrm()
            name = GROUP3[reg & 7]
            if name == "test":
                imm = self._i16() if self.opsize == 16 else self._i32()
                return "test", f"{rm},{_imm(imm, self.opsize)}"
            return name, rm
        if b == 0xF6:
            reg, rm = self._modrm(8)
            name = GROUP3[reg & 7]
            if name == "test":
                return "test", f"{rm},{_imm(self._u8(), 8)}"
            return name, rm

        if b == 0xFF:
            reg = (self.code[self.pos] >> 3) & 7
            name = GROUP5[reg]
            if name is None:
                raise Undecodable("FF /7 is not an instruction")
            # call, jmp and push default to 64-bit operands in long mode -- no
            # REX.W needed, and `jmp rax` is not `jmp eax`.
            size = 64 if name in ("call", "jmp", "push") else self.opsize
            _, rm = self._modrm(size)
            return name, rm

        if b == 0x0F:
            return self._opcode_0f(self._u8())

        raise Undecodable(f"unknown opcode {b:#04x}")

    def _opcode_0f(self, b: int) -> tuple[str, str]:
        if b == 0x05:
            return "syscall", ""
        if b == 0x0B:
            return "ud2", ""
        if b == 0x1F:                             # multi-byte nop
            _, rm = self._modrm()
            return "nop", rm
        if b == 0xAF:
            reg, rm = self._modrm()
            return "imul", f"{self._reg(reg)},{rm}"
        if 0x80 <= b <= 0x8F:                     # jcc rel32
            rel = self._i32()
            return "j" + CONDITIONS[b - 0x80], _target(self.base + self.pos + rel)
        if 0x90 <= b <= 0x9F:                     # setcc r/m8
            _, rm = self._modrm(8)
            return "set" + CONDITIONS[b - 0x90], rm
        if 0x40 <= b <= 0x4F:                     # cmovcc
            reg, rm = self._modrm()
            return "cmov" + CONDITIONS[b - 0x40], f"{self._reg(reg)},{rm}"
        if b in (0xB6, 0xB7, 0xBE, 0xBF):         # movzx / movsx
            src_size = 8 if b in (0xB6, 0xBE) else 16
            name = "movzx" if b in (0xB6, 0xB7) else "movsx"
            dst = self.opsize
            reg, rm = self._modrm(src_size)
            saved, self.opsize = self.opsize, dst
            out = f"{self._reg(reg)},{rm}"
            self.opsize = saved
            return name, out
        raise Undecodable(f"unknown opcode 0f {b:#04x}")


def disassemble(code: bytes, base: int = 0) -> list[Insn]:
    """Decode straight through `code`. Stops at the first byte it cannot read."""
    dec = Decoder(code, base)
    out = []
    while dec.pos < len(code):
        mark = dec.pos
        try:
            out.append(dec.decode_one())
        except Undecodable:
            dec.pos = mark
            break
    return out
