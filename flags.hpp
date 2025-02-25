#include <cstdint>
enum EFlags {
  CF = 0,
  PF = 2,
  AF = 4,
  ZF = 6,
  SF = 7,
  TF = 8,
  IF = 9,
  DF = 10,
  OF = 11,
  IOPL1 = 12,
  IOPL2 = 13,
  NT = 14,
  MD = 15,  // Always 1 on 8086/186, 0 on 286 and later
  RF = 16,  // Resume flag (386+ only)
  VM = 17,  // Virtual 8086 mode (386+ only)
  AC = 18,  // Alignment Check (486+, ring 3), SMAP Access Check (Broadwell+,
            // ring 0-2)
  VIF = 19, // Virtual Interrupt Flag (Pentium+, ring 3)
  VIP = 20, // Virtual Interrupt Pending (Pentium+, ring 3)
  ID = 21,  // CPUID detection flag (486+ only)
};

inline void set_flag(uint32_t &flags, EFlags flag) {
  flags |= (1ULL << static_cast<uint64_t>(flag));
}

inline void clear_flag(uint32_t &flags, EFlags flag) {
  flags &= ~(1ULL << static_cast<uint64_t>(flag));
}

inline bool test_flag(uint32_t flags, EFlags flag) {
  return (flags & (1ULL << static_cast<uint64_t>(flag))) != 0;
}