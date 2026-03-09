#pragma once

enum ht68_reg_t
{
  HT68_R_A = 0,
  HT68_R_STATUS,
  HT68_R_PCL,
  HT68_R_BP,
  HT68_R_MP0,
  HT68_R_MP1L,
  HT68_R_MP1H,
  HT68_R_IAR0,
  HT68_R_IAR1,
  HT68_R_TBLP,
  HT68_R_TBHP,
  HT68_R_TBLH,
  HT68_R_PC,
  HT68_R_SP,
  HT68_R_VCS,
  HT68_R_VDS,
  HT68_R_LAST
};

extern const char *const ht68_reg_names[HT68_R_LAST];
