#include "virtual_cpu.hpp"
#include "x86.h"

void CPU::execute_return() { this->pop(X86_REG_EIP); }

void CPU::execute_call(const cs_insn *insn) {
  std::cout << "Call instruction detected!" << std::endl;
  const cs_x86 &x86 = insn->detail->x86;

  if (x86.op_count <= 0) {
    std::cerr << "Error: No operands found!" << std::endl;
    throw std::runtime_error("No operands found in CALL instruction!");
  }
  const cs_x86_op &op = x86.operands[0];
  switch (op.type) {
  case X86_OP_IMM:
    std::cout << "Calling relative address: 0x" << std::hex << op.imm
              << std::dec << std::endl;
    push(insn->address + insn->size);
    eip = op.imm; // Capstone returns the target address value for CALL imm
    break;
  case X86_OP_MEM:
    std::cout << "Indirect call via memory address" << std::endl;
    std::cout << "Base: " << cs_reg_name(handle, op.mem.base) << std::endl;
    std::cout << "Index: " << cs_reg_name(handle, op.mem.index) << std::endl;
    std::cout << "Scale: " << op.mem.scale << std::endl;
    std::cout << "Displacement: " << op.mem.disp << std::endl;
    break;
  case X86_OP_REG:
    std::cout << "Indirect call via register: " << cs_reg_name(handle, op.reg)
              << std::endl;
    break;
  case X86_OP_INVALID:
    std::cerr << "Invalid operand!" << std::endl;
    throw std::runtime_error("Invalid operand in CALL instruction!");
  }
}

void CPU::execute_jmp(const cs_insn *insn) {
  std::cout << "Jump instruction detected!" << std::endl;
  const cs_x86 &x86 = insn->detail->x86;

  if (x86.op_count <= 0) {
    std::cerr << "Error: No operands found!" << std::endl;
    throw std::runtime_error("No operands found in JMP instruction!");
  }
  const cs_x86_op &op = x86.operands[0];

  switch (op.type) {
  case X86_OP_INVALID: {
    std::cerr << "Invalid operand!" << std::endl;
    throw std::runtime_error("Invalid operand in JMP instruction!");
  } break;
  case X86_OP_REG: {
    std::cout << "Jumping to register: " << cs_reg_name(handle, op.reg)
              << std::endl;
    throw std::runtime_error("JMP to register not supported!");
  } break;
  case X86_OP_IMM:
    std::cout << "Jumping to relative address: 0x" << std::hex << op.imm
              << std::dec << std::endl;
    eip = op.imm; // Capstone returns the target address value for JMP imm
    break;
  case X86_OP_MEM: {
    std::cout << "Indirect jump via memory address" << std::endl;
    std::cout << "Base: " << cs_reg_name(handle, op.mem.base) << std::endl;
    std::cout << "Index: " << cs_reg_name(handle, op.mem.index) << std::endl;
    std::cout << "Scale: " << op.mem.scale << std::endl;
    std::cout << "Displacement: " << op.mem.disp << std::endl;
    throw std::runtime_error("Indirect JMP not supported!");
  } break;
  }
}