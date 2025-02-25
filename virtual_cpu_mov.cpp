#include "virtual_cpu.hpp"
#include "x86.h"

void CPU::execute_mov(const cs_insn *insn) {
  std::cout << "Mov instruction detected!" << std::endl;
  const cs_x86 &x86 = insn->detail->x86;

  if (x86.op_count <= 0) {
    std::cerr << "Error: No operands found!" << std::endl;
    throw std::runtime_error("No operands found in MOV instruction!");
  }
  const cs_x86_op &op1 = x86.operands[0];
  const cs_x86_op &op2 = x86.operands[1];
  // read operand 2
  int value;
  switch (op2.type) {
  case X86_OP_REG: {
    std::cout << "Moving from register: " << cs_reg_name(handle, op2.reg)
              << std::endl;
    value = read_register(op2.reg);
    break;
  }
  case X86_OP_IMM: {
    std::cout << "Moving immediate value: " << op2.imm << std::endl;
    value = op2.imm;
    break;
  }
  case X86_OP_MEM: {
    std::cout << "Moving from memory" << std::endl;
    uint32_t address = calculate_operand_memory(op2.mem);
    value = read_memory(address, op2.size);
    break;
  }
  case X86_OP_INVALID: {
    std::cerr << "Invalid operand!" << std::endl;
    throw std::runtime_error("Invalid operand in MOV instruction!");
  } break;
  }

  // write to operand 1
  switch (op1.type) {
  case X86_OP_REG: {
    std::cout << "Moving to register: " << cs_reg_name(handle, op1.reg)
              << std::endl;
    write_register(op1.reg, value);
    break;
  }
  case X86_OP_MEM: {
    std::cout << "Moving to memory" << std::endl;
    uint32_t address = calculate_operand_memory(op1.mem);
    write_memory(address, value, op1.size);
    break;
  }
  case X86_OP_IMM: {
    std::cerr << "Immediate operand not supported!" << std::endl;
    throw std::runtime_error("Immediate operand in MOV instruction!");
  } break;
  case X86_OP_INVALID: {
    std::cerr << "Invalid operand!" << std::endl;
    throw std::runtime_error("Invalid operand in MOV instruction!");
  } break;
  }
}
