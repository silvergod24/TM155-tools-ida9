#include "ht68.hpp"

namespace
{
static void out_direct_mem(outctx_t &ctx, const op_t &x)
{
  ctx.out_symbol('[');
  if (!ctx.out_name_expr(x, x.addr, BADADDR))
    ctx.out_value(x, OOF_ADDR | OOFW_16);
  ctx.out_symbol(']');
}

static void out_bit_suffix(outctx_t &ctx)
{
  const uint8 bit = uint8((ctx.insn.auxpref & HT68_AUX_BIT_MASK) >> HT68_AUX_BIT_SHIFT);
  ctx.out_symbol('.');
  op_t bitop;
  bitop.type = o_imm;
  bitop.dtype = dt_byte;
  bitop.value = bit;
  ctx.out_value(bitop, OOFW_8);
}

static inline void out_acc(outctx_t &ctx)
{
  ctx.out_register(ht68_reg_names[HT68_R_A]);
}

static bool insn_uses_acc_prefix(const insn_t &insn)
{
  switch (insn.itype)
  {
    case HT68_sbc_k:
    case HT68_ret_k:
    case HT68_sub_k:
    case HT68_add_k:
    case HT68_xor_k:
    case HT68_or_k:
    case HT68_and_k:
    case HT68_mov_k:
    case HT68_mov_am:
      return true;
    default:
      return false;
  }
}
} // namespace

bool idaapi ht68_out_operand(outctx_t &ctx, const op_t &x)
{
  switch (x.type)
  {
    case o_imm:
      ctx.out_value(x, OOFW_8);
      return true;

    case o_near:
      if (!ctx.out_name_expr(x, x.addr, BADADDR))
      {
        ctx.out_tagon(COLOR_ERROR);
        ctx.out_btoa(x.addr, 16);
        ctx.out_tagoff(COLOR_ERROR);
      }
      return true;

    case o_mem:
      out_direct_mem(ctx, x);
      if ((ctx.insn.auxpref & HT68_AUX_BITOP) != 0 && &x == &ctx.insn.Op1)
        out_bit_suffix(ctx);
      return true;

    default:
      return false;
  }
}

void idaapi ht68_out_insn(outctx_t &ctx)
{
  ctx.out_mnemonic();

  if (ctx.insn.itype == HT68_mov_ma)
  {
    ctx.out_one_operand(0);
    ctx.out_symbol(',');
    ctx.out_char(' ');
    out_acc(ctx);
    ctx.set_gen_cmt();
    ctx.flush_outbuf();
    return;
  }

  if (insn_uses_acc_prefix(ctx.insn))
  {
    out_acc(ctx);
    if (ctx.insn.Op1.type != o_void)
    {
      ctx.out_symbol(',');
      ctx.out_char(' ');
      ctx.out_one_operand(0);
    }
    ctx.set_gen_cmt();
    ctx.flush_outbuf();
    return;
  }

  for (int i = 0; i < UA_MAXOP; ++i)
  {
    const op_t &op = ctx.insn.ops[i];
    if (op.type == o_void)
      break;
    if (i == 0)
      ctx.out_one_operand(i);
    else
    {
      ctx.out_symbol(',');
      ctx.out_char(' ');
      ctx.out_one_operand(i);
    }
  }

  ctx.set_gen_cmt();
  ctx.flush_outbuf();
}
