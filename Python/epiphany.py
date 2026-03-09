"""
Adapteva Epiphany eCore processor module (IDA Pro 9.3, IDAPython).

Source policy:
- Instruction names/syntax/registers/memory map were taken from:
  Epiphany Architecture Reference Manual (REV 14.03.11).
- The opcode decode bitmasks are intentionally omitted because
  "Table 66: Epiphany Instruction Decode Table" is not machine-readable in
  the available web text extraction.
"""

from ida_bytes import *  # noqa: F401,F403
from ida_diskio import get_user_idadir
from ida_idaapi import BADADDR
from ida_idp import *  # noqa: F401,F403
from ida_lines import *  # noqa: F401,F403
from ida_netnode import *  # noqa: F401,F403
from ida_problems import *  # noqa: F401,F403
from ida_segment import *  # noqa: F401,F403
from ida_typeinf import *  # noqa: F401,F403
from ida_ua import *  # noqa: F401,F403
from ida_xref import *  # noqa: F401,F403

import ida_bytes
import idc

import json
import os
import traceback


EPOP_NONE = 0
EPOP_RD_RN_OP2 = 1
EPOP_RD_RN_RM = 2
EPOP_RD_RN = 3
EPOP_RD_IMM = 4
EPOP_BRANCH = 5
EPOP_REG_JUMP = 6
EPOP_LDST = 7
EPOP_TESTSET = 8
EPOP_MOVTS = 9
EPOP_MOVFS = 10
EPOP_TRAP = 11


IDEF_MAGIC_VALUE = 0
IDEF_MASK = 1
IDEF_MNEMONIC = 2
IDEF_OP_TYPE = 3
IDEF_IDA_FEATURE = 4
IDEF_COMMENT = 5


# Manual-derived instruction catalog (Section 7.6, Tables 10-16).
DOC_INSTRUCTIONS = [
    ("bcond", EPOP_BRANCH, CF_USE1 | CF_JUMP, "Conditional branch (B<COND>)."),
    ("b", EPOP_BRANCH, CF_USE1 | CF_STOP, "Unconditional branch."),
    ("bl", EPOP_BRANCH, CF_USE1 | CF_CALL, "Branch and link."),
    ("jr", EPOP_REG_JUMP, CF_USE1 | CF_STOP, "Register jump."),
    ("jalr", EPOP_REG_JUMP, CF_USE1 | CF_CALL, "Register jump and link."),
    ("ldr", EPOP_LDST, CF_CHG1 | CF_USE2, "Load from memory."),
    ("str", EPOP_LDST, CF_USE1 | CF_USE2 | CF_CHG2, "Store to memory."),
    ("testset", EPOP_TESTSET, CF_CHG1 | CF_USE2, "Atomic test-and-set."),
    ("add", EPOP_RD_RN_OP2, CF_CHG1 | CF_USE2, "Integer addition."),
    ("sub", EPOP_RD_RN_OP2, CF_CHG1 | CF_USE2, "Integer subtraction."),
    ("asr", EPOP_RD_RN_OP2, CF_CHG1 | CF_USE2, "Arithmetic right shift."),
    ("lsr", EPOP_RD_RN_OP2, CF_CHG1 | CF_USE2, "Logical right shift."),
    ("lsl", EPOP_RD_RN_OP2, CF_CHG1 | CF_USE2, "Logical left shift."),
    ("orr", EPOP_RD_RN_RM, CF_CHG1 | CF_USE2, "Logical OR."),
    ("and", EPOP_RD_RN_RM, CF_CHG1 | CF_USE2, "Logical AND."),
    ("eor", EPOP_RD_RN_RM, CF_CHG1 | CF_USE2, "Logical XOR."),
    ("bitr", EPOP_RD_RN, CF_CHG1 | CF_USE2, "Bit reverse."),
    ("fadd", EPOP_RD_RN_RM, CF_CHG1 | CF_USE2, "Floating-point add."),
    ("fsub", EPOP_RD_RN_RM, CF_CHG1 | CF_USE2, "Floating-point subtract."),
    ("fmul", EPOP_RD_RN_RM, CF_CHG1 | CF_USE2, "Floating-point multiply."),
    ("fmadd", EPOP_RD_RN_RM, CF_CHG1 | CF_USE2, "Floating-point multiply-add."),
    ("fmsub", EPOP_RD_RN_RM, CF_CHG1 | CF_USE2, "Floating-point multiply-sub."),
    ("fabs", EPOP_RD_RN, CF_CHG1 | CF_USE2, "Floating-point absolute."),
    ("fix", EPOP_RD_RN, CF_CHG1 | CF_USE2, "Float to fixed conversion."),
    ("float", EPOP_RD_RN, CF_CHG1 | CF_USE2, "Fixed to float conversion."),
    ("iadd", EPOP_RD_RN_RM, CF_CHG1 | CF_USE2, "Secondary integer add."),
    ("isub", EPOP_RD_RN_RM, CF_CHG1 | CF_USE2, "Secondary integer sub."),
    ("imul", EPOP_RD_RN_RM, CF_CHG1 | CF_USE2, "Secondary integer multiply."),
    ("imadd", EPOP_RD_RN_RM, CF_CHG1 | CF_USE2, "Secondary integer multiply-add."),
    ("imsub", EPOP_RD_RN_RM, CF_CHG1 | CF_USE2, "Secondary integer multiply-sub."),
    ("mov", EPOP_RD_IMM, CF_CHG1 | CF_USE2, "Move immediate."),
    ("movt", EPOP_RD_IMM, CF_CHG1 | CF_USE2, "Move immediate high-half."),
    ("movcond", EPOP_RD_RN, CF_CHG1 | CF_USE2, "Conditional register move."),
    ("movts", EPOP_MOVTS, CF_USE1 | CF_CHG2, "Move to special register."),
    ("movfs", EPOP_MOVFS, CF_CHG1 | CF_USE2, "Move from special register."),
    ("nop", EPOP_NONE, 0, "No operation."),
    ("idle", EPOP_NONE, CF_STOP, "Idle until interrupt."),
    ("rts", EPOP_NONE, CF_STOP, "Return from subroutine."),
    ("rti", EPOP_NONE, CF_STOP, "Return from interrupt."),
    ("gid", EPOP_NONE, 0, "Global interrupt disable."),
    ("gie", EPOP_NONE, 0, "Global interrupt enable."),
    ("bkpt", EPOP_NONE, CF_STOP, "Breakpoint."),
    ("mbkpt", EPOP_NONE, CF_STOP, "Multicore breakpoint."),
    ("trap", EPOP_TRAP, CF_STOP, "Software trap."),
    ("sync", EPOP_NONE, 0, "Multicore sync."),
    ("wand", EPOP_NONE, 0, "Multicore barrier flag."),
    ("und", EPOP_NONE, 0, "Undecoded halfword."),
]


# TODO: Table 66 omitted due to missing/ambiguous documentation.
# This list must be populated with source-backed bitmasks/magic values.
INSN_DEFS = []


class NiceEnum(object):
    pass


itypes = NiceEnum()
MNEMONIC_TO_ITYPE = {}
INSTRUC_LIST = []
for idx, item in enumerate(DOC_INSTRUCTIONS):
    mnem, _, feature, _ = item
    enum_name = "i_" + mnem.replace("<", "").replace(">", "").replace("-", "_")
    setattr(itypes, enum_name, idx)
    MNEMONIC_TO_ITYPE[mnem] = idx
    INSTRUC_LIST.append({"name": mnem, "feature": feature})


def _json_paths():
    user_dir = get_user_idadir() + "/procs"
    local_dir = os.path.dirname(__file__)
    return [
        os.path.join(user_dir, "epiphany.json"),
        os.path.join(local_dir, "epiphany.json"),
    ]


def load_reg_defs():
    for path in _json_paths():
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


REG_DEFS = load_reg_defs()


def iter_register_entries(reg_db):
    if isinstance(reg_db, list):
        return reg_db

    if not isinstance(reg_db, dict):
        return []

    entries = []

    gpr = reg_db.get("general_registers", {})
    if isinstance(gpr, dict):
        try:
            base = int(str(gpr["base"]), 16)
            count = int(gpr["count"])
            stride = int(gpr.get("stride", 4))
            prefix = str(gpr.get("prefix", "R"))
            comment = str(gpr.get("comment", "General purpose register"))
            for idx in range(count):
                entries.append(
                    {
                        "address": "0x%X" % (base + (idx * stride)),
                        "name": "%s%d" % (prefix, idx),
                        "access": "RD/WR",
                        "comment": comment,
                    }
                )
        except Exception:
            pass

    special = reg_db.get("special_registers", [])
    if isinstance(special, list):
        entries.extend(special)

    return entries


def get_itype_for_opcode(opcode):
    for i, idef in enumerate(INSN_DEFS):
        magic = idef[IDEF_MAGIC_VALUE]
        mask = idef[IDEF_MASK]
        if (opcode & mask) == magic:
            return i
    return None


class EpiphanyProcessor(processor_t):
    id = 0x8000 + 933
    flag = PRN_HEX

    cnbits = 8
    dnbits = 8
    segreg_size = 0
    tbyte_size = 0

    psnames = ["epiphany"]
    plnames = ["Adapteva Epiphany eCore"]

    assembler = {
        "flag": AS_N2CHR | ASH_HEXF0 | ASD_DECF0,
        "uflag": 0,
        "name": "GNU as (Epiphany)",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": '"\'',
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".short",
        "a_dword": ".long",
        "a_qword": ".quad",
        "a_bss": ".space %s",
        "a_equ": ".equ",
        "a_seg": "seg",
        "a_curip": ".",
        "a_public": ".global",
        "a_weak": ".weak",
        "a_extrn": ".extern",
        "a_comdef": ".comm",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "sizeof(%s)",
    }

    reg_names = ["R%d" % i for i in range(64)] + ["CS", "DS"]
    reg_first_sreg = 64
    reg_last_sreg = 65
    reg_code_sreg = 64
    reg_data_sreg = 65

    instruc_start = 0

    def __init__(self):
        processor_t.__init__(self)
        self.instruc = INSTRUC_LIST
        self.instruc_end = len(self.instruc)
        self.icode_return = MNEMONIC_TO_ITYPE.get("rts", MNEMONIC_TO_ITYPE["und"])

    def _ensure_mmr_segment(self):
        seg_name = "EPMMR"
        if get_segm_by_name(seg_name):
            return

        # Safe fixed address from architecture memory map (Table 6).
        mmr_start = 0xF0000
        mmr_end = 0xF0800

        seg = segment_t()
        seg.start_ea = mmr_start
        seg.end_ea = mmr_end
        seg.align = saAbs
        seg.comb = scPriv
        seg.bitness = 1
        seg.type = SEG_IMEM
        add_segm_ex(seg, seg_name, "DATA", ADDSEG_NOSREG)

    def _prepare_db(self):
        regs = iter_register_entries(REG_DEFS)
        if not regs:
            return

        for reg in regs:
            try:
                ea = int(reg["address"], 16)
                name = str(reg["name"])
                comment = str(reg.get("comment", ""))
                bits = reg.get("bits")

                ida_bytes.create_data(ea, ida_bytes.FF_DWORD, 4, BADADDR)
                idc.set_name(ea, "MMR_" + name, idc.SN_NOWARN)
                if comment:
                    idc.set_cmt(ea, comment, 1)

                if not bits:
                    continue

                enum_name = "bit_" + name.lower()
                enum_id = idc.add_enum(BADADDR, enum_name, 0)
                if enum_id == BADADDR:
                    enum_id = idc.get_enum(enum_name)
                for bit_index, bit_name in enumerate(bits):
                    if not bit_name:
                        continue
                    try:
                        idc.add_enum_member(
                            enum_id,
                            "{}:{}".format(name, bit_name),
                            bit_index,
                            -1,
                        )
                    except Exception:
                        pass
            except Exception:
                traceback.print_exc()

    def notify_init(self, idp_file):
        self.helper = netnode()
        self.helper.create("$ epiphany")

    def notify_newfile(self, fname):
        self._ensure_mmr_segment()
        self._prepare_db()

    def notify_oldfile(self, fname):
        self._ensure_mmr_segment()
        self._prepare_db()

    def notify_ana(self, insn):
        # Decode one instruction at insn.ea.
        # Manual indicates 16-bit and 32-bit instruction forms.
        # Without Table 66 bitmasks, default to halfword stepping.
        opcode = get_wide_word(insn.ea)
        insn.size = 2

        # Required by IDA 9.x constraint in user prompt.
        insn.Op1.type = o_void
        insn.Op2.type = o_void

        itype = get_itype_for_opcode(opcode)
        if itype is None:
            insn.itype = MNEMONIC_TO_ITYPE["und"]
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = opcode
            return insn.size

        # TODO: Instruction operand decode omitted due missing/ambiguous documentation.
        insn.itype = itype
        return insn.size

    def _poke_operand(self, insn, op, read_flag, write_flag):
        if op.type == o_mem:
            if read_flag != 0:
                add_dref(insn.ea, op.addr, dr_R)
            if write_flag != 0:
                add_dref(insn.ea, op.addr, dr_W)
        elif op.type == o_near and read_flag != 0:
            add_cref(insn.ea, op.addr, fl_JN)

    def notify_emu(self, insn):
        try:
            feature = insn.get_canon_feature()
            flow = (feature & CF_STOP) == 0

            if (feature & CF_CALL) and insn.Op1.type == o_near:
                add_cref(insn.ea, insn.Op1.addr, fl_CN)
            elif (feature & CF_JUMP) and insn.Op1.type == o_near:
                add_cref(insn.ea, insn.Op1.addr, fl_JN)
                flow = False

            self._poke_operand(insn, insn.Op1, feature & CF_USE1, feature & CF_CHG1)
            self._poke_operand(insn, insn.Op2, feature & CF_USE2, feature & CF_CHG2)

            if flow:
                add_cref(insn.ea, insn.ea + insn.size, fl_F)
            return 1
        except Exception:
            traceback.print_exc()
            return 1

    def notify_out_operand(self, ctx, op):
        try:
            optype = op.type
            if optype == o_reg:
                ctx.out_register(self.reg_names[op.reg])
            elif optype == o_imm:
                ctx.out_value(op, OOFW_IMM | OOF_SIGNED)
            elif optype == o_mem or optype == o_near:
                ok = ctx.out_name_expr(op, op.addr, BADADDR)
                if not ok:
                    ctx.out_tagon(COLOR_ERROR)
                    ctx.out_btoa(op.addr, 16)
                    ctx.out_tagoff(COLOR_ERROR)
                    remember_problem(PR_NONAME, ctx.insn.ea)
            else:
                return -1
            return 1
        except Exception:
            traceback.print_exc()
            return -1

    def notify_out_insn(self, ctx):
        try:
            insn = ctx.insn
            ctx.out_mnem()
            for i in range(0, 2):
                op = insn[i]
                if op.type == o_void:
                    continue
                if i > 0:
                    ctx.out_symbol(",")
                    ctx.out_char(" ")
                ctx.out_one_operand(i)
            ctx.set_gen_cmt()
            ctx.flush_outbuf()
            return 1
        except Exception:
            traceback.print_exc()
            return 0

    def notify_get_autocmt(self, insn):
        try:
            return DOC_INSTRUCTIONS[insn.itype][3]
        except Exception:
            return "Undecoded instruction halfword."


def PROCESSOR_ENTRY():
    return EpiphanyProcessor()
