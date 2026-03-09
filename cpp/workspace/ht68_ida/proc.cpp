#include "ht68.hpp"
#include <segment.hpp>

static const char *const shnames[] = { "ht68fb", "ht8", nullptr };
static const char *const lnames[] = { "Holtek HT68FB540/550/560 (HT8 core)", nullptr };

static const asm_t ht68_asm =
{
  ASH_HEXF3 | ASD_DECF0 | ASB_BINF0 | ASO_OCTF0 | AS_N2CHR,
  0,
  "Holtek HT68 style assembler",
  0,
  nullptr,
  ".org",
  ".end",
  ";",
  '"',
  '\'',
  "\\\"'",
  ".ascii",
  ".db",
  ".dw",
  ".dd",
  nullptr,
  nullptr,
  "ds %s",
  ".equ",
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  nullptr
};

static const asm_t *const asms[] = { &ht68_asm, nullptr };

static const uchar retcode_ret[] = { 0x03, 0x00 };
static const uchar retcode_reti[] = { 0x04, 0x00 };
static const bytes_t retcodes[] =
{
  { sizeof(retcode_ret), retcode_ret },
  { sizeof(retcode_reti), retcode_reti },
  { 0, nullptr }
};

struct ht68_procmod_t : public procmod_t
{
  static void ensure_ram_segment()
  {
    if (getseg(HT68_RAM_BASE) != nullptr)
      return;

    // Provide a stable home for direct-memory operands [m].
    add_segm(0, HT68_RAM_BASE, HT68_RAM_BASE + HT68_RAM_SIZE, "RAM", "DATA");
  }

  ssize_t idaapi on_event(ssize_t msgid, va_list va) override
  {
    switch (msgid)
    {
      case processor_t::ev_init:
        msg("[ht68fb] IDP loaded (build 2026-03-09)\n");
        inf_set_be(false);
        return 1;

      case processor_t::ev_newfile:
      case processor_t::ev_oldfile:
      case processor_t::ev_newprc:
        inf_set_be(false);
        ensure_ram_segment();
        return 1;

      case processor_t::ev_ana_insn:
        return ht68_ana(va_arg(va, insn_t *));

      case processor_t::ev_emu_insn:
        return ht68_emu(*va_arg(va, const insn_t *));

      case processor_t::ev_out_insn:
        ht68_out_insn(*va_arg(va, outctx_t *));
        return 1;

      case processor_t::ev_out_operand:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const op_t *op = va_arg(va, const op_t *);
        return ht68_out_operand(*ctx, *op) ? 1 : -1;
      }

      case processor_t::ev_get_autocmt:
      {
        qstring *buf = va_arg(va, qstring *);
        const insn_t *insn = va_arg(va, const insn_t *);
        if (buf == nullptr || insn == nullptr)
          return 0;
        const char *cmt = ht68_get_autocmt(*insn);
        if (cmt == nullptr || *cmt == '\0')
          return 0;
        *buf = cmt;
        return 1;
      }

      case processor_t::ev_is_basic_block_end:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        const int call_stops = va_arg(va, int);
        qnotused(call_stops);
        switch (insn->itype)
        {
          case HT68_jmp:
          case HT68_ret:
          case HT68_reti:
          case HT68_ret_k:
          case HT68_halt:
            return 1;
          default:
            return -1;
        }
      }

      case processor_t::ev_is_sane_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        const int no_crefs = va_arg(va, int);
        qnotused(no_crefs);
        if (insn->itype <= HT68_null || insn->itype >= HT68_last)
          return 0;
        return insn->size == 2 ? 1 : -1;
      }

      default:
        break;
    }
    return 0;
  }
};

static ssize_t idaapi notify(void *, int msgid, va_list va)
{
  if (msgid == processor_t::ev_get_procmod)
    return ssize_t(new ht68_procmod_t());
  qnotused(va);
  return 0;
}

processor_t LPH =
{
  IDP_INTERFACE_VERSION,
  0x8000 + 0x68F,
  PRN_HEX | PR_WORD_INS | PR_RNAMESOK,
  0,
  8,
  8,
  shnames,
  lnames,
  asms,
  notify,
  ht68_reg_names,
  qnumber(ht68_reg_names),
  HT68_R_VCS,
  HT68_R_VDS,
  0,
  HT68_R_VCS,
  HT68_R_VDS,
  nullptr,
  retcodes,
  HT68_null,
  HT68_last,
  Instructions,
  0,
  { 0, 0, 0, 0 },
  HT68_ret
};
