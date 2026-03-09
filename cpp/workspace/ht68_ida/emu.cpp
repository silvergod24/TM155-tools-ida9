#include "ht68.hpp"

namespace
{
enum mem_acc_t
{
  MA_NONE = 0,
  MA_READ = 1,
  MA_WRITE = 2,
  MA_READWRITE = 3
};

static mem_acc_t mem_access_type(int itype)
{
  switch (itype)
  {
    case HT68_mov_ma:
    case HT68_subm:
    case HT68_addm:
    case HT68_xorm:
    case HT68_orm:
    case HT68_andm:
    case HT68_swap:
    case HT68_sbcm:
    case HT68_adcm:
    case HT68_inc:
    case HT68_dec:
    case HT68_siz:
    case HT68_sdz:
    case HT68_rl:
    case HT68_rr:
    case HT68_rlc:
    case HT68_rrc:
    case HT68_daa:
    case HT68_clr:
    case HT68_set:
    case HT68_setb:
    case HT68_clrb:
      return MA_READWRITE;

    case HT68_ret_k:
      return MA_NONE;

    case HT68_cpla:
    case HT68_sub:
    case HT68_add:
    case HT68_xor:
    case HT68_or:
    case HT68_and:
    case HT68_mov_am:
    case HT68_sza:
    case HT68_sz:
    case HT68_swapa:
    case HT68_sbc:
    case HT68_adc:
    case HT68_inca:
    case HT68_deca:
    case HT68_siza:
    case HT68_sdza:
    case HT68_rla:
    case HT68_rra:
    case HT68_rlca:
    case HT68_rrca:
    case HT68_snz:
    case HT68_snzb:
    case HT68_szb:
      return MA_READ;

    case HT68_itabrdc:
    case HT68_itabrdl:
    case HT68_tabrdc:
    case HT68_tabrdl:
      return MA_WRITE;

    case HT68_cpl:
      return MA_READWRITE;

    default:
      return MA_NONE;
  }
}

static void add_mem_refs(const insn_t &insn, const op_t &op)
{
  if (op.type != o_mem || op.addr == BADADDR)
    return;

  const mem_acc_t ma = mem_access_type(insn.itype);
  if (ma == MA_NONE)
    return;

  if ((ma & MA_READ) != 0)
    insn.add_dref(op.addr, op.offb, dr_R);
  if ((ma & MA_WRITE) != 0)
    insn.add_dref(op.addr, op.offb, dr_W);
}

static void add_near_cref(const insn_t &insn, const op_t &op, bool is_call)
{
  if (op.type != o_near || op.addr == BADADDR)
    return;
  insn.add_cref(op.addr, op.offb, is_call ? fl_CN : fl_JN);
}
} // namespace

int idaapi ht68_emu(const insn_t &insn)
{
  const uint32 feat = Instructions[insn.itype].feature;

  if ((feat & CF_USE1) != 0 && insn.Op1.type == o_imm)
    set_immd(insn.ea);

  if ((feat & (CF_USE1 | CF_CHG1)) != 0 && insn.Op1.type == o_mem)
  {
    add_mem_refs(insn, insn.Op1);
  }

  if (insn.itype == HT68_call)
  {
    add_near_cref(insn, insn.Op1, true);
  }
  else if (insn.itype == HT68_jmp)
  {
    add_near_cref(insn, insn.Op1, false);
    return 1;
  }

  if (ht68_is_skip_itype(insn.itype))
  {
    const ea_t next = insn.ea + insn.size;
    const ea_t skip = next + 2;
    insn.add_cref(next, 0, fl_F);
    insn.add_cref(skip, 0, fl_JN);
    return 1;
  }

  if ((feat & CF_STOP) == 0)
    insn.add_cref(insn.ea + insn.size, 0, fl_F);

  return 1;
}
