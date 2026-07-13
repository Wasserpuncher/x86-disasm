import pytest

from x86disasm.decode import Decoder, Undecodable, disassemble


def one(hexstr: str, base: int = 0):
    code = bytes.fromhex(hexstr.replace(" ", ""))
    ins = Decoder(code, base).decode_one()
    assert ins.length == len(code), f"decoded {ins.length} of {len(code)} bytes"
    return str(ins)


# -- the basics ----------------------------------------------------------

def test_push_rbp():
    assert one("55") == "push rbp"


def test_mov_rbp_rsp():
    assert one("48 89 e5") == "mov rbp,rsp"


def test_ret():
    assert one("c3") == "ret"


def test_rex_b_extends_the_register_number():
    assert one("41 54") == "push r12"


# -- the traps -----------------------------------------------------------

def test_bare_rex_switches_the_8bit_register_file():
    # 0x40 is a REX with no bits set. It still changes which 8-bit registers
    # are addressable: without it, reg 7 is `bh`; with it, `dil`.
    assert one("84 ff") == "test bh,bh"
    assert one("40 84 ff") == "test dil,dil"


def test_operand_size_prefix_shrinks_the_immediate():
    # 0x66 makes this a 16-bit operation, so the immediate is 2 bytes, not 4.
    # Reading 4 would swallow the next instruction.
    assert one("66 3d 00 30") == "cmp ax,0x3000"
    assert one("3d 00 30 00 00") == "cmp eax,0x3000"


def test_modrm_101_with_mod_00_is_rip_relative_not_rbp():
    ins = Decoder(bytes.fromhex("488d3d91ffffff"), 0).decode_one()
    assert ins.length == 7
    assert "rip" in ins.operands
    assert ins.rip_target == 0x7 - 0x6F & 0xFFFFFFFFFFFFFFFF


def test_immediates_are_bit_patterns_not_signed_numbers():
    # `and rsp,-0x10` and `and rsp,0xfffffffffffffff0` are the same 64 bits.
    # objdump prints what the CPU sees.
    assert one("48 83 e4 f0") == "and rsp,0xfffffffffffffff0"


def test_lock_prefix_is_not_dropped():
    # `lock sub` is atomic; `sub` is not. Swallowing the prefix would turn a
    # thread-safe instruction into a racy one in the listing.
    assert one("f0 48 83 0c 24 00") == "lock or QWORD PTR [rsp],0x0"


def test_fs_segment_is_kept():
    # The stack canary lives at fs:0x28. Dropping the segment loses what the
    # instruction actually reads.
    assert one("64 48 8b 04 25 28 00 00 00") == "mov rax,QWORD PTR fs:0x28"


def test_ff_group_defaults_to_64bit_in_long_mode():
    assert one("ff e0") == "jmp rax"
    assert one("ff 55 c0") == "call QWORD PTR [rbp-0x40]"


def test_0x90_is_only_a_nop_without_prefixes():
    assert one("90") == "nop"
    assert one("66 90") == "xchg ax,ax"


def test_movabs_takes_a_full_64bit_immediate():
    assert one("48 b8 cd cc cc cc cc cc cc cc") == "movabs rax,0xcccccccccccccccd"


def test_sib_scale_is_printed_even_when_it_is_one():
    assert one("0f b6 34 02") == "movzx esi,BYTE PTR [rdx+rax*1]"


def test_zero_displacement_is_still_printed_when_encoded():
    # mod=01 with disp8=0 is a real byte on the wire, so objdump shows it.
    assert one("49 03 5d 00") == "add rbx,QWORD PTR [r13+0x0]"


def test_branch_targets_wrap_into_64_bits():
    assert one("e8 ab ff ff ff") == "call 0xffffffffffffffb0"


# -- error handling ------------------------------------------------------

def test_unknown_opcode_raises():
    with pytest.raises(Undecodable):
        Decoder(b"\x0f\xff", 0).decode_one()


def test_truncated_instruction_raises():
    with pytest.raises(Undecodable):
        Decoder(b"\x48\x81", 0).decode_one()      # needs an imm32 that is not there


def test_disassemble_stops_cleanly_at_bytes_it_cannot_read():
    insns = disassemble(bytes.fromhex("55 48 89 e5 0f ff"))
    assert [str(i) for i in insns] == ["push rbp", "mov rbp,rsp"]
