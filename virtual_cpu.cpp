#include "virtual_cpu.hpp"
#include "flags.hpp"
#include "x86.h"
#include <cstdint>

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
  case X86_OP_MEM: {
    std::cout << "Indirect call via memory address" << std::endl;
    uint32_t target_address = calculate_operand_memory(op.mem);
    std::cout << "Target address: 0x" << std::hex << target_address << std::dec
              << std::endl;
    push(insn->address + insn->size);
    eip = target_address;
    break;
  }
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

void CPU::execute_je(const cs_insn *insn) {
  std::cout << "JE instruction detected!" << std::endl;
  const cs_x86 &x86 = insn->detail->x86;

  if (x86.op_count <= 0) {
    std::cerr << "Error: No operands found!" << std::endl;
    throw std::runtime_error("No operands found in JE instruction!");
  }
  const cs_x86_op &op = x86.operands[0];

  switch (op.type) {
  case X86_OP_INVALID: {
    std::cerr << "Invalid operand!" << std::endl;
    throw std::runtime_error("Invalid operand in JE instruction!");
  } break;
  case X86_OP_REG: {
    throw std::runtime_error("JE to register not supported!");
  } break;
  case X86_OP_IMM:
    std::cout << "Comparing relative address: 0x" << std::hex << op.imm
              << std::dec << std::endl;
    if (test_flag(eflags, ZF)) {
      std::cout << "ZF is set, jumping to 0x" << std::hex << op.imm << std::dec
                << std::endl;
      eip = op.imm; // Capstone returns the target address value for JE imm
    }
    break;
  case X86_OP_MEM: {
    std::cout << "Indirect compare via memory address" << std::endl;
    std::cout << "Base: " << cs_reg_name(handle, op.mem.base) << std::endl;
    std::cout << "Index: " << cs_reg_name(handle, op.mem.index) << std::endl;
    std::cout << "Scale: " << op.mem.scale << std::endl;
    std::cout << "Displacement: " << op.mem.disp << std::endl;
    throw std::runtime_error("Indirect JE not supported!");
  } break;
  }
}

void CPU::execute_jne(const cs_insn *insn) {
  std::cout << "JNE instruction detected!" << std::endl;
  const cs_x86 &x86 = insn->detail->x86;

  if (x86.op_count <= 0) {
    std::cerr << "Error: No operands found!" << std::endl;
    throw std::runtime_error("No operands found in JNE instruction!");
  }
  const cs_x86_op &op = x86.operands[0];

  switch (op.type) {
  case X86_OP_INVALID: {
    std::cerr << "Invalid operand!" << std::endl;
    throw std::runtime_error("Invalid operand in JNE instruction!");
  } break;
  case X86_OP_REG: {
    throw std::runtime_error("JNE to register not supported!");
  } break;
  case X86_OP_IMM:
    std::cout << "Comparing relative address: 0x" << std::hex << op.imm
              << std::dec << std::endl;
    if (!test_flag(eflags, ZF)) {
      std::cout << "ZF is not set, jumping to 0x" << std::hex << op.imm
                << std::dec << std::endl;
      eip = op.imm; // Capstone returns the target address value for JNE imm
    }
    break;
  case X86_OP_MEM: {
    std::cout << "Indirect compare via memory address" << std::endl;
    std::cout << "Base: " << cs_reg_name(handle, op.mem.base) << std::endl;
    std::cout << "Index: " << cs_reg_name(handle, op.mem.index) << std::endl;
    std::cout << "Scale: " << op.mem.scale << std::endl;
    std::cout << "Displacement: " << op.mem.disp << std::endl;
    throw std::runtime_error("Indirect JNE not supported!");
  } break;
  }
}