#pragma once

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <ua.hpp>

#include "regs.hpp"
#include "ins.hpp"

extern processor_t LPH;

ssize_t idaapi ht68_ana(insn_t *insn);
int idaapi ht68_emu(const insn_t &insn);
void idaapi ht68_out_insn(outctx_t &ctx);
bool idaapi ht68_out_operand(outctx_t &ctx, const op_t &x);
const char *idaapi ht68_get_autocmt(const insn_t &insn);

constexpr uint16 HT68_AUX_BITOP = 0x0001;
constexpr uint16 HT68_AUX_BIT_SHIFT = 8;
constexpr uint16 HT68_AUX_BIT_MASK = 0x0700;

constexpr uint16 HT68_CALL_ADDR_BITS = 13;
constexpr uint16 HT68_CALL_BANK_WORDS = 0x2000;
constexpr uint16 HT68_CALL_ADDR_MASK = (1u << HT68_CALL_ADDR_BITS) - 1u;
constexpr ea_t HT68_RAM_BASE = 0x8000;
constexpr ea_t HT68_RAM_SIZE = 0x0100;

inline uint16 ht68_read_word(ea_t ea)
{
  return uint16(get_wide_word(ea) & 0xFFFFu);
}

inline uint16 ht68_low14(uint16 iw)
{
  return uint16(iw & 0x3FFFu);
}

inline uint8 ht68_m8(uint16 iw)
{
  return uint8((((iw >> 14) & 0x1u) << 7) | (iw & 0x7Fu));
}

inline uint16 ht68_k13(uint16 iw)
{
  return uint16(((((iw >> 14) & 0x3u) << 11) | (iw & 0x7FFu)) & HT68_CALL_ADDR_MASK);
}

inline ea_t ht68_data_ea(const insn_t &insn, uint8 m)
{
  qnotused(insn);
  // Direct mode addresses map into a dedicated synthetic RAM window.
  // TODO(ht68): refine this mapping with BP banking/model-specific RAM layout.
  return HT68_RAM_BASE + ea_t(m);
}

inline ea_t ht68_code_ea(const insn_t &insn, uint16 abs_word)
{
  const ea_t bank_span = ea_t(HT68_CALL_BANK_WORDS) * 2;
  const ea_t bank_base = insn.ea & ~(bank_span - 1);
  return bank_base + (ea_t(abs_word) * 2);
}

inline bool ht68_is_skip_itype(int itype)
{
  switch (itype)
  {
    case HT68_sza:
    case HT68_sz:
    case HT68_szb:
    case HT68_snz:
    case HT68_snzb:
    case HT68_siz:
    case HT68_siza:
    case HT68_sdz:
    case HT68_sdza:
      return true;
    default:
      return false;
  }
}
