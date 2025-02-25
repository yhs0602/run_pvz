#include "capstone.h"
#include "virtual_cpu.hpp"
#include "x86.h"

void CPU::execute_pop(const cs_insn *insn) {
  std::cout << "Pop instruction detected!" << std::endl;
  const cs_x86 &x86 = insn->detail->x86;

  if (x86.op_count <= 0) {
    std::cerr << "Error: No operands found!" << std::endl;
    throw std::runtime_error("No operands found in POP instruction!");
  }
  const cs_x86_op &op = x86.operands[0];
  switch (op.type) {
  case X86_OP_REG:
    std::cout << "Popping into register: " << cs_reg_name(handle, op.reg)
              << std::endl;
    pop(op.reg);
    break;
  case X86_OP_MEM: {
    uint32_t address = calculate_operand_memory(op.mem);
    popmem(address);
    break;
  }
  case X86_OP_INVALID:
    std::cerr << "Invalid operand!" << std::endl;
    throw std::runtime_error("Invalid operand in POP instruction!");
  case X86_OP_IMM:
    std::cerr << "Immediate operand not supported!" << std::endl;
    throw std::runtime_error("Immediate operand in POP instruction!");
  }
}

void CPU::execute_push(const cs_insn *insn) {
  std::cout << "Push instruction detected!" << std::endl;
  const cs_x86 &x86 = insn->detail->x86;

  if (x86.op_count <= 0) {
    std::cerr << "Error: No operands found!" << std::endl;
    throw std::runtime_error("No operands found in PUSH instruction!");
  }
  const cs_x86_op &op = x86.operands[0];
  switch (op.type) {
  case X86_OP_REG:
    std::cout << "Pushing register: " << cs_reg_name(handle, op.reg)
              << std::endl;
    push(read_register(op.reg));
    break;
  case X86_OP_IMM:
    std::cout << "Pushing immediate value: " << op.imm << std::endl;
    push(op.imm);
    break;
  case X86_OP_MEM: {
    uint32_t address = calculate_operand_memory(op.mem);
    pushmem(address, op.size);
    break;
  }
  case X86_OP_INVALID:
    std::cerr << "Invalid operand!" << std::endl;
    throw std::runtime_error("Invalid operand in PUSH instruction!");
  }
}