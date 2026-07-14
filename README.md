# x86-disasm

**An x86-64 disassembler in pure Python. 333 005 instructions from five system binaries, decoded byte-identically to GNU objdump. Zero disagreements.**

x86 instructions have no fixed length. You cannot know where the next one
starts until you have fully decoded this one — and decoding means walking a
state machine where every part changes how the next part is read:

```
[prefixes] [REX] opcode [ModRM] [SIB] [displacement] [immediate]
```

Get one length wrong and you don't just misprint an operand. You resume
decoding *in the middle of an instruction*, and every byte after that is
garbage. That's what makes this a satisfying thing to build: it either works
completely, or it visibly falls apart.

## The one number that matters

Point it at real compiler output and let a known-correct disassembler judge it:

```console
$ python -m x86disasm verify /usr/bin/git

/usr/bin/git
  instructions:  ~61,412
  decoded:       ~59,349  (~96.6%)
  wrong length:   0
  wrong text:     0
  exact:         ~59,349  (100.0000%)
```

The tildes are there because those counts belong to *your* `git` binary, not
mine — a different build has a different number of instructions in it. The two
numbers that carry the claim have no tilde and never will: **wrong length: 0**
and **wrong text: 0**. Those must be zero on any binary, on any machine.

Across five binaries — bash, objdump, gcc, git and glibc:

| binary | instructions | wrong length | disagreements with objdump |
| --- | ---: | ---: | ---: |
| bash | 67 528 | 0 | 0 |
| objdump | 68 519 | 0 | 0 |
| gcc | 72 342 | 0 | 0 |
| git | 59 349 | 0 | 0 |
| libc.so.6 | 65 267 | 0 | 0 |
| **total** | **333 005** | **0** | **0** |

**96.6 %** of the instructions in those binaries get decoded; the rest are SSE
and AVX, which this doesn't implement. Of the ones it does decode, **100.0000 %
come out byte-for-byte identical to objdump** — same length, same mnemonic,
same operands.

## It reads back what tinyjit writes

This is the other half of [tinyjit](https://github.com/Wasserpuncher/tinyjit),
which compiles a small language to real x86-64 machine code. That project emits
bytes; this one turns them back into instructions. The circle closes:

<!-- readme-check: skip=braucht-tinyjit -->
```console
$ python -m tinyjit dump examples/fib.tj | ...
00000000  55                              push rbp
00000001  48 89 e5                        mov rbp,rsp
00000004  48 81 ec 20 00 00 00            sub rsp,0x20
0000000b  48 89 bd f8 ff ff ff            mov QWORD PTR [rbp-0x8],rdi
00000020  48 b8 02 00 00 00 00 00 00 00   movabs rax,0x2
00000034  48 39 c8                        cmp rax,rcx
00000037  0f 9c c0                        setl al
0000003a  48 0f b6 c0                     movzx rax,al
```

All 45 instructions of tinyjit's `fib()` — identical to objdump.

## Use it

```console
$ python -m x86disasm dump /usr/bin/ls --section --limit 64
$ python -m x86disasm verify /usr/bin/bash
```

```python
from x86disasm import disassemble

for ins in disassemble(bytes.fromhex("554889e5")):
    print(f"{ins.addr:04x}  {ins.raw.hex(' '):<12}  {ins}")
# 0000  55            push rbp
# 0001  48 89 e5      mov rbp,rsp
```

## The parts that bite

Every one of these is a real bug that the objdump comparison caught, and each
is pinned by a test:

- **`0x40` is a REX prefix with no bits set — and it still matters.** It changes
  which 8-bit registers exist: `84 ff` is `test bh,bh`, but `40 84 ff` is
  `test dil,dil`. Testing the REX *bits* misses this; you have to test its
  presence.
- **A `0x66` prefix shrinks the immediate.** `66 3d 00 30` is `cmp ax,0x3000` —
  four bytes, not six. Read an imm32 anyway and you eat the next instruction.
- **`mod=00 rm=101` does not mean `[rbp]`.** It is the one encoding that means
  RIP-relative, and it carries a disp32 that you will otherwise not read.
- **`lock` is not decoration.** `lock sub` is atomic and `sub` is not. A
  disassembler that drops the prefix is lying about thread safety.
- **`fs:` is not decoration either.** `mov rax, QWORD PTR fs:0x28` is the stack
  canary. Drop the segment and you've lost what the instruction touches.
- **Immediates are bit patterns, not numbers.** `and rsp,-0x10` and
  `and rsp,0xfffffffffffffff0` are the same 64 bits; objdump prints the second,
  because that is what the CPU sees.
- **`ff /2` and `ff /4` are 64-bit without a REX.** In long mode `call`, `jmp`
  and `push` default to 64-bit operands — it's `jmp rax`, never `jmp eax`.

## Run the verification yourself

```console
$ python -m pytest -q
24 passed
```

The suite disassembles the `.text` of whatever real binaries it finds on your
machine and compares every instruction against objdump. A wrong length is a
hard failure — that is the one error a disassembler cannot survive.

## Limits

- **No SSE/AVX/x87.** The 3.4 % it skips are `movaps`, `pxor`, `punpcklqdq` and
  friends. It reports them as undecodable rather than guessing — a decoder that
  invents an answer is worse than one that admits it doesn't know.
- **Intel syntax only**, to match `objdump -M intel`.
- **No symbolisation.** Addresses, not function names.

## Install

```console
$ git clone https://github.com/Wasserpuncher/x86-disasm
$ cd x86-disasm
$ python -m x86disasm verify /usr/bin/bash
```

Python 3.10+, no dependencies. `objdump` (binutils) is needed only for `verify`
and the test suite — the disassembler itself needs nothing.

## License

MIT
