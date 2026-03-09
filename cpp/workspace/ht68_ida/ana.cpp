#include "ht68.hpp"

namespace
{
static inline void clear_insn(insn_t &insn)
{
  insn.itype = HT68_null;
  insn.size = 0;
  insn.auxpref = 0;
  for (int i = 0; i < UA_MAXOP; ++i)
    insn.ops[i].type = o_void;
}

static inline void set_mem(insn_t &insn, op_t &op, uint8 m)
{
  op.type = o_mem;
  op.addr = ht68_data_ea(insn, m);
  op.dtype = dt_byte;
  op.offb = 0;
  op.set_shown();
}

static inline void set_imm(op_t &op, uint16 v)
{
  op.type = o_imm;
  op.value = v;
  op.dtype = dt_byte;
  op.offb = 0;
  op.set_shown();
}

static inline void set_near(op_t &op, ea_t target)
{
  op.type = o_near;
  op.addr = target;
  op.dtype = dt_code;
  op.offb = 0;
  op.set_shown();
}

static inline void set_bitinfo(insn_t &insn, uint8 bit)
{
  insn.auxpref |= HT68_AUX_BITOP;
  insn.auxpref &= ~HT68_AUX_BIT_MASK;
  insn.auxpref |= uint16(bit & 0x7u) << HT68_AUX_BIT_SHIFT;
}
} // namespace

ssize_t idaapi ht68_ana(insn_t *insn)
{
  clear_insn(*insn);

  // Holtek HT68FB family opcodes are fixed 1-word instructions.
  const uint16 iw = ht68_read_word(insn->ea);
  const uint16 lo14 = ht68_low14(iw);
  const uint8 m = ht68_m8(iw);
  const uint8 d = uint8((lo14 >> 7) & 0x1u);
  const uint8 op3 = uint8((lo14 >> 8) & 0x7u);
  const uint8 grp = uint8((lo14 >> 11) & 0x7u);

  // Fixed control opcodes in the legacy low range.
  if ((iw & 0xFFC0u) == 0)
  {
    switch (iw & 0x003Fu)
    {
      case 0x00: insn->itype = HT68_nop; break;
      case 0x01: insn->itype = HT68_clrwdt1; break;
      case 0x02: insn->itype = HT68_halt; break;
      case 0x03: insn->itype = HT68_ret; break;
      case 0x04: insn->itype = HT68_reti; break;
      case 0x05: insn->itype = HT68_clrwdt2; break;
      default: break;
    }
    if (insn->itype != HT68_null)
    {
      insn->size = 2;
      return insn->size;
    }
  }

  // CALL/JMP absolute forms. 16-bit variants carry extra high address bits.
  if (grp == 0x4 || grp == 0x5)
  {
    insn->itype = (grp == 0x4) ? HT68_call : HT68_jmp;
    set_near(insn->Op1, ht68_code_ea(*insn, ht68_k13(iw)));
    insn->size = 2;
    return insn->size;
  }

  // Bit operations on direct memory.
  if ((lo14 >> 12) == 0x3)
  {
    const uint8 bop = uint8((lo14 >> 10) & 0x3u);
    const uint8 bit = uint8((lo14 >> 7) & 0x7u);
    set_mem(*insn, insn->Op1, m);
    set_bitinfo(*insn, bit);

    switch (bop)
    {
      case 0x0: insn->itype = HT68_setb; break;
      case 0x1: insn->itype = HT68_clrb; break;
      case 0x2: insn->itype = HT68_snzb; break;
      case 0x3: insn->itype = HT68_szb;  break;
      default: break;
    }

    if (insn->itype != HT68_null)
    {
      insn->size = 2;
      return insn->size;
    }
  }

  // Immediate group.
  if (grp == 0x1)
  {
    const uint8 imm_grp = uint8((lo14 >> 8) & 0x7u);
    set_imm(insn->Op1, lo14 & 0xFFu);
    switch (imm_grp)
    {
      case 0x0: insn->itype = HT68_sbc_k; break;
      case 0x1: insn->itype = HT68_ret_k; break;
      case 0x2: insn->itype = HT68_sub_k; break;
      case 0x3: insn->itype = HT68_add_k; break;
      case 0x4: insn->itype = HT68_xor_k; break;
      case 0x5: insn->itype = HT68_or_k;  break;
      case 0x6: insn->itype = HT68_and_k; break;
      case 0x7: insn->itype = HT68_mov_k; break;
      default: break;
    }
    insn->size = 2;
    return insn->size;
  }

  // Group 000: arithmetic/logic core and direct MOV forms.
  if (grp == 0x0)
  {
    if (op3 == 0x0)
    {
      if (d == 1)
      {
        insn->itype = HT68_mov_ma;
        set_mem(*insn, insn->Op1, m);
        insn->size = 2;
        return insn->size;
      }
      return 0;
    }

    switch (op3)
    {
      case 0x1: insn->itype = (d == 0) ? HT68_cpla : HT68_cpl; break;
      case 0x2: insn->itype = (d == 0) ? HT68_sub  : HT68_subm; break;
      case 0x3: insn->itype = (d == 0) ? HT68_add  : HT68_addm; break;
      case 0x4: insn->itype = (d == 0) ? HT68_xor  : HT68_xorm; break;
      case 0x5: insn->itype = (d == 0) ? HT68_or   : HT68_orm; break;
      case 0x6: insn->itype = (d == 0) ? HT68_and  : HT68_andm; break;
      case 0x7:
        if (d != 0)
          return 0;
        insn->itype = HT68_mov_am;
        break;
      default:
        return 0;
    }

    set_mem(*insn, insn->Op1, m);
    insn->size = 2;
    return insn->size;
  }

  // Group 010: ALU/skip forms.
  if (grp == 0x2)
  {
    switch (op3)
    {
      case 0x0: insn->itype = (d == 0) ? HT68_sza   : HT68_sz; break;
      case 0x1: insn->itype = (d == 0) ? HT68_swapa : HT68_swap; break;
      case 0x2: insn->itype = (d == 0) ? HT68_sbc   : HT68_sbcm; break;
      case 0x3: insn->itype = (d == 0) ? HT68_adc   : HT68_adcm; break;
      case 0x4: insn->itype = (d == 0) ? HT68_inca  : HT68_inc; break;
      case 0x5: insn->itype = (d == 0) ? HT68_deca  : HT68_dec; break;
      case 0x6: insn->itype = (d == 0) ? HT68_siza  : HT68_siz; break;
      case 0x7: insn->itype = (d == 0) ? HT68_sdza  : HT68_sdz; break;
      default: return 0;
    }
    set_mem(*insn, insn->Op1, m);
    insn->size = 2;
    return insn->size;
  }

  // Group 011: rotates, table reads, and memory utility operations.
  if (grp == 0x3)
  {
    switch (op3)
    {
      case 0x0: insn->itype = (d == 0) ? HT68_rla    : HT68_rl; break;
      case 0x1: insn->itype = (d == 0) ? HT68_rra    : HT68_rr; break;
      case 0x2: insn->itype = (d == 0) ? HT68_rlca   : HT68_rlc; break;
      case 0x3: insn->itype = (d == 0) ? HT68_rrca   : HT68_rrc; break;
      case 0x4: insn->itype = (d == 0) ? HT68_itabrdc: HT68_itabrdl; break;
      case 0x5: insn->itype = (d == 0) ? HT68_tabrdc : HT68_tabrdl; break;
      case 0x6: insn->itype = (d == 0) ? HT68_snz    : HT68_daa; break;
      case 0x7: insn->itype = (d == 0) ? HT68_clr    : HT68_set; break;
      default: return 0;
    }
    set_mem(*insn, insn->Op1, m);
    insn->size = 2;
    return insn->size;
  }

  return 0;
}
