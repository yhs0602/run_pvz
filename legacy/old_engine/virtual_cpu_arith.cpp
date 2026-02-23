#include "flags.hpp"
#include "virtual_cpu.hpp"

void CPU::execute_sub(const cs_insn *insn) {
  std::cout << "Sub instruction detected!" << std::endl;
  const cs_x86 &x86 = insn->detail->x86;
  int op1 = read_operand(x86.operands[0]);
  int op2 = read_operand(x86.operands[1]);
  int result = op1 - op2;
  write_operand(x86.operands[0], result);
  // TODO: OF, AF, CF
  update_sign_flag(result);
  update_zero_flag(result);
  update_parity_flag(result);
}

void CPU::execute_add(const cs_insn *insn) {
  // OF, SF, ZF, AF, PF, CF
  std::cout << "Add instruction detected!" << std::endl;
  const cs_x86 &x86 = insn->detail->x86;
  int op1 = read_operand(x86.operands[0]);
  int op2 = read_operand(x86.operands[1]);
  int result = op1 - op2;
  write_operand(x86.operands[0], result);

  // TODO: OF, AF, CF
  update_sign_flag(result);
  update_zero_flag(result);
  update_parity_flag(result);
}

void CPU::execute_and(const cs_insn *insn) {
  std::cout << "And instruction detected!" << std::endl;
  const cs_x86 &x86 = insn->detail->x86;
  int op1 = read_operand(x86.operands[0]);
  int op2 = read_operand(x86.operands[1]);
  int result = op1 & op2;
  write_operand(x86.operands[0], result);
  clear_flag(eflags, OF);
  update_sign_flag(result);
  update_zero_flag(result);
  update_parity_flag(result);
  clear_flag(eflags, CF);
}

void CPU::execute_xor(const cs_insn *insn) {
  std::cout << "Xor instruction detected!" << std::endl;
  const cs_x86 &x86 = insn->detail->x86;
  int op1 = read_operand(x86.operands[0]);
  int op2 = read_operand(x86.operands[1]);
  int result = op1 ^ op2;
  write_operand(x86.operands[0], result);
  clear_flag(eflags, OF);
  update_sign_flag(result);
  update_zero_flag(result);
  update_parity_flag(result);
  clear_flag(eflags, CF);
}

void CPU::execute_or(const cs_insn *insn) {
  std::cout << "Or instruction detected!" << std::endl;
  const cs_x86 &x86 = insn->detail->x86;
  int op1 = read_operand(x86.operands[0]);
  int op2 = read_operand(x86.operands[1]);
  int result = op1 | op2;
  write_operand(x86.operands[0], result);
  clear_flag(eflags, OF);
  update_sign_flag(result);
  update_zero_flag(result);
  update_parity_flag(result);
  clear_flag(eflags, CF);
}

void CPU::update_parity_flag(int result) {
  int count = 0;
  for (int i = 0; i < 8; i++) {
    if (result & (1 << i)) {
      count++;
    }
  }
  if ((count % 2) == 0) {
    set_flag(eflags, PF);
  } else {
    clear_flag(eflags, PF);
  }
}

void CPU::update_sign_flag(int result) {
  if (result < 0) {
    set_flag(eflags, SF);
  } else {
    clear_flag(eflags, SF);
  }
}

void CPU::update_zero_flag(int result) {
  if (result == 0) {
    set_flag(eflags, ZF);
  } else {
    clear_flag(eflags, ZF);
  }
}

void CPU::execute_test(const cs_insn *insn) {
  std::cout << "Test instruction detected!" << std::endl;
  const cs_x86 &x86 = insn->detail->x86;
  int op1 = read_operand(x86.operands[0]);
  int op2 = read_operand(x86.operands[1]);
  int result = op1 & op2;
  // OF = 0; SF, ZF, PF; CF = 0
  clear_flag(eflags, OF);
  clear_flag(eflags, CF);
  update_sign_flag(result);
  update_zero_flag(result);
  update_parity_flag(result);
}

void CPU::execute_cmp(const cs_insn *insn) {
  std::cout << "Cmp instruction detected!" << std::endl;
  const cs_x86 &x86 = insn->detail->x86;
  int op1 = read_operand(x86.operands[0]);
  int op2 = read_operand(x86.operands[1]);
  int result = op1 - op2;
  // OF, SF, ZF, AF, PF, CF
  update_sign_flag(result);
  update_zero_flag(result);
  update_parity_flag(result);
  if (op1 < op2) {
    set_flag(eflags, CF);
  } else {
    clear_flag(eflags, CF);
  }
}