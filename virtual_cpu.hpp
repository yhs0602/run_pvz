#include "capstone.h"
#include "x86.h"
#include <cstdint>
#include <iostream>
#include <map>
#include <vector>

constexpr uint32_t TEB_BASE = 0xFFFDF000; // 에뮬레이터에서 TEB의 가짜 주소
constexpr uint32_t PEB_BASE = 0x7FFD8000; // PEB의 가짜 주소
constexpr uint32_t STACK_BASE = 0x003FFFFC;
constexpr uint32_t STACK_SIZE = 0x1000;
constexpr uint32_t PAGE_SIZE = 0x1000;

class CPU {
public:
  int eax, ebx, ecx, edx;
  int esi, edi, ebp, eip, esp;
  short cs, ds, es, fs, gs, ss;
  uint32_t eflags;
  csh handle;

  std::map<int, std::vector<uint8_t>> memory;
  // for debug purpose.
  std::stack<int> stack;

  CPU(const csh handle, const uint32_t entry_point) {
    eax = 1;
    ebx = 0;
    ecx = 0; // argc
    edx = 0; // envp
    esi = 0; // argv[0]
    edi = 0;
    ebp = 0;
    esp = STACK_BASE;
    eip = entry_point;
    eflags = 0x202; // IF = 1
    fs = 0x38;      // FS:[0] = TEB
    gs = 0;
    ss = 0;
    cs = 0;
    ds = 0;
    es = 0;
    this->handle = handle;

    initialize_teb();
  }

  void initialize_teb();

  void pushad() {
    push(eax);
    push(ecx);
    push(edx);
    push(ebx);
    push(esp);
    push(ebp);
    push(esi);
    push(edi);
  }
  void popad() {
    pop(X86_REG_EDI);
    pop(X86_REG_ESI);
    pop(X86_REG_EBP);
    pop(X86_REG_ESP);
    pop(X86_REG_EBX);
    pop(X86_REG_EDX);
    pop(X86_REG_ECX);
    pop(X86_REG_EAX);
  }
  void pushf() { push(eflags); }
  void popf() {
    eflags = read_memory(esp);
    esp += 4;
  }

  void push(int value) {
    esp -= 4;
    write_memory(esp, value);
    stack.push(value);
  }

  void pop(const x86_reg reg) {
    int value = read_memory(esp);
    esp += 4;
    write_register(reg, value);
    stack.pop();
  }

  void pushmem(uint32_t address, int size = 4) {
    int value = read_memory(address, size);
    esp -= 4;
    write_memory(esp, value);
    stack.push(value);
  }

  void popmem(uint32_t address) {
    int value = read_memory(esp);
    esp += 4;
    write_memory(address, value);
    stack.pop();
  }

  int read_memory(uint32_t address, int size = 4);

  // memory
  void write_memory(uint32_t address, int value, int size = 4);

  int read_register(const x86_reg reg) {
    switch (reg) {
    case X86_REG_EAX:
      return eax;
    case X86_REG_EBX:
      return ebx;
    case X86_REG_ECX:
      return ecx;
    case X86_REG_EDX:
      return edx;
    case X86_REG_ESI:
      return esi;
    case X86_REG_EDI:
      return edi;
    case X86_REG_EBP:
      return ebp;
    case X86_REG_ESP:
      return esp;
    case X86_REG_EIP:
      return eip;
    case X86_REG_CS:
      return cs;
    case X86_REG_DS:
      return ds;
    case X86_REG_ES:
      return es;
    case X86_REG_FS:
      return fs;
    case X86_REG_GS:
      return gs;
    case X86_REG_SS:
      return ss;
    default:
      throw std::runtime_error("Invalid register!");
    }
  }

  void write_register(x86_reg reg, int value) {
    switch (reg) {
    case X86_REG_EAX:
      eax = value;
      break;
    case X86_REG_EBX:
      ebx = value;
      break;
    case X86_REG_ECX:
      ecx = value;
      break;
    case X86_REG_EDX:
      edx = value;
      break;
    case X86_REG_ESI:
      esi = value;
      break;
    case X86_REG_EDI:
      edi = value;
      break;
    case X86_REG_EBP:
      ebp = value;
      break;
    case X86_REG_ESP:
      esp = value;
      break;
    case X86_REG_EIP:
      eip = value;
      break;
    case X86_REG_CS:
      cs = value;
      break;
    case X86_REG_DS:
      ds = value;
      break;
    case X86_REG_ES:
      es = value;
      break;
    case X86_REG_FS:
      fs = value;
      break;
    case X86_REG_GS:
      gs = value;
      break;
    case X86_REG_SS:
      ss = value;
      break;
    default:
      throw std::runtime_error("Invalid register!");
    }
  }

  inline void dump_register(const char *name, x86_reg reg) {
    int value = read_register(reg);
    if (value != 0) {
      std::cout << name << ": 0x" << std::hex << value << std::dec << std::endl;
    }
  }

  void dump() {
    std::cout << "===== Registers:" << std::endl;
    dump_register("EAX", X86_REG_EAX);
    dump_register("EBX", X86_REG_EBX);
    dump_register("ECX", X86_REG_ECX);
    dump_register("EDX", X86_REG_EDX);
    dump_register("ESI", X86_REG_ESI);
    dump_register("EDI", X86_REG_EDI);
    dump_register("EBP", X86_REG_EBP);
    dump_register("ESP", X86_REG_ESP);
    dump_register("EIP", X86_REG_EIP);
    dump_register("CS", X86_REG_CS);
    dump_register("DS", X86_REG_DS);
    dump_register("ES", X86_REG_ES);
    dump_register("FS", X86_REG_FS);
    dump_register("GS", X86_REG_GS);
    dump_register("SS", X86_REG_SS);
    std::cout << "EFLAGS: 0x" << std::hex << eflags << std::dec << std::endl;
    std::cout << "== Stack ==" << std::endl;
    // duplicate stack before printing
    std::stack<int> stack_copy = stack;
    while (!stack_copy.empty()) {
      std::cout << "0x" << std::hex << stack_copy.top() << std::dec
                << std::endl;
      stack_copy.pop();
    }
  }

  void execute_return();
  void execute_call(const cs_insn *insn);
  void execute_jmp(const cs_insn *insn);
  void execute_mov(const cs_insn *insn);
  void execute_lea(const cs_insn *insn);
  void execute_push(const cs_insn *insn);
  void execute_pop(const cs_insn *insn);

  void execute_je(const cs_insn *insn);
  void execute_jne(const cs_insn *insn);

  void update_parity_flag(int result);
  void update_sign_flag(int result);
  void update_zero_flag(int result);

  void execute_add(const cs_insn *insn);
  void execute_sub(const cs_insn *insn);
  void execute_mul(const cs_insn *insn);
  void execute_div(const cs_insn *insn);
  void execute_and(const cs_insn *insn);
  void execute_or(const cs_insn *insn);
  void execute_xor(const cs_insn *insn);
  void extracted(int &result);
  void execute_test(const cs_insn *insn);
  void execute_cmp(const cs_insn *insn);
  uint32_t translate_gdt(short segment_value);
  uint32_t calculate_operand_memory(const x86_op_mem &operand);
  int read_operand(const cs_x86_op &op) {
    switch (op.type) {
    case X86_OP_REG:
      return read_register(op.reg);
    case X86_OP_IMM:
      return op.imm;
    case X86_OP_MEM:
      return read_memory(calculate_operand_memory(op.mem), op.size);
    default:
      throw std::runtime_error("Invalid operand type!");
    }
  }
  void write_operand(const cs_x86_op &op, int value) {
    switch (op.type) {
    case X86_OP_REG:
      write_register(op.reg, value);
      break;
    case X86_OP_MEM:
      write_memory(calculate_operand_memory(op.mem), value, op.size);
      break;
    default:
      throw std::runtime_error("Invalid operand type!");
    }
  }
};