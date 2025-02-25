#include <LIEF/LIEF.hpp>
#include <capstone/capstone.h>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <span>
#include <vector>

void disassemble_x86(const std::vector<uint8_t> &code, uint64_t address) {
  csh handle;
  cs_insn *insn;
  size_t count;

  if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
    std::cerr << "Failed to initialize Capstone!" << std::endl;
    return;
  }

  count = cs_disasm(handle, code.data(), code.size(), address, 0, &insn);
  if (count > 0) {
    for (size_t i = 0; i < count; i++) {
      std::cout << std::hex << insn[i].address << ": " << insn[i].mnemonic
                << " " << insn[i].op_str << std::endl;
    }
    cs_free(insn, count);
  } else {
    std::cerr << "Disassembly failed!" << std::endl;
  }

  cs_close(&handle);
}

// returns the offset of the next instruction
int execute_one_instruction(const csh handle, const cs_insn *insn) {
  std::cout << std::hex << insn->address << ": " << insn->mnemonic << " "
            << insn->op_str << std::endl;
  switch (insn->id) {
  case X86_INS_CALL: {
    std::cout << "Call instruction detected! Detail:" << insn->detail
              << std::endl;
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
      return (insn->address + insn->size) + op.imm;
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
    break;
  }
  case X86_INS_RET:
    std::cout << "Return instruction detected!" << std::endl;
    break;
  }
  return 0;
}

void execute_x86(const std::span<const uint8_t> &code, uint64_t start_offset,
                 uint64_t address) {
  csh handle;
  size_t count;

  if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
    std::cerr << "Failed to initialize Capstone!" << std::endl;
    return;
  }
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  cs_insn *insn = cs_malloc(handle);
  if (insn == nullptr) {
    std::cerr << "Failed to allocate memory for instruction!" << std::endl;
    return;
  }

  std::cout << "Executing from entry point...\n";

  const uint8_t *current_code_ptr = (code.data() + start_offset);
  size_t code_size = code.size();
  uint64_t virtaddr = address;
  while (true) {
    count = cs_disasm_iter(handle, &current_code_ptr, &code_size, &virtaddr, insn);
    if (count == 1) {
      int next_instruction_offset = execute_one_instruction(handle, insn);
      if (next_instruction_offset > 0) {
        std::cout << "Next instruction offset: " << next_instruction_offset
                  << std::endl;
      }
      break;
    } else {
      std::cerr << "Disassembly failed!" << std::endl;
      break;
    }
  }
  cs_free(insn, 1);
  cs_close(&handle);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <PE file>" << std::endl;
    return 1;
  }

  auto binary = LIEF::PE::Parser::parse(argv[1]);
  if (!binary) {
    std::cerr << "Failed to parse PE file!" << std::endl;
    return 1;
  }

  std::cout << "PE Machine Type: "
            << static_cast<int>(binary->header().machine()) << std::endl;
  std::cout << "Number of Sections: " << binary->sections().size() << std::endl;

  LIEF::PE::Section *text_section = nullptr;
  // setCodeSectionBase(oph.getBaseOfCode());
  // setCodeSectionLimit(getCodeSectionBase() + oph.getSizeOfCode());
  // setCodeVirtAddr(oph.getImageBase() + getCodeSectionBase());
  // binary->optional_header().addressof_entrypoint()
  // setEntryPoint(oph.getAddressOfEntryPoint());
  // fileContents = filec;
  for (const auto &section : binary->sections()) {
    std::cout << "Section Name: " << section.name() << std::endl;
    std::cout << "Size: " << section.size() << " bytes" << std::endl;
    std::cout << "Virtual Address: " << section.virtual_address() << std::endl;
    std::cout << "Raw Offset: " << section.offset() << std::endl;
    std::cout << "=========================" << std::endl;

    if (section.name() == ".text") {
      text_section = const_cast<LIEF::PE::Section *>(&section);
    }
  }
  uint64_t entry_point_va = binary->optional_header().addressof_entrypoint();
  std::cout << "Entry Point Address (VA): 0x" << std::hex << entry_point_va
            << std::dec << std::endl;

  if (!text_section) {
    std::cerr << "Error: No .text section found!" << std::endl;
    return 1;
  }

  uint64_t entry_offset = entry_point_va - text_section->virtual_address() +
                          text_section->pointerto_raw_data();
  std::cout << "Corrected Entry Point Offset in file: 0x" << std::hex
            << entry_offset << std::dec << std::endl;

  // 엔트리포인트의 파일 내 오프셋 계산
  std::cout << "Entry Point Virtual Address: 0x" << std::hex << entry_point_va
            << std::dec << std::endl;
  std::cout << ".text Section Virtual Address: 0x" << std::hex
            << text_section->virtual_address() << std::dec << std::endl;
  std::cout << ".text Section Raw Offset: 0x" << std::hex
            << text_section->offset() << std::dec << std::endl;
  std::cout << "Calculated Entry Point Offset: 0x" << std::hex << entry_offset
            << std::dec << std::endl;

  // Read the PE file to get the code section content
  std::ifstream pe_file(argv[1], std::ios::binary);
  if (!pe_file) {
    std::cerr << "Error opening PE file!" << std::endl;
    return 1;
  }
  // Read the entire code section
  auto text_content = text_section->content();
  uint64_t entry_point_offset_in_text =
      entry_point_va - text_section->virtual_address();
  std::cout << "Entry Point Offset in .text section: 0x" << std::hex
            << entry_point_offset_in_text << std::dec << std::endl;

  // // 엔트리포인트 주변 코드(256바이트) 읽기
  // pe_file.seekg(entry_offset);
  // std::vector<uint8_t> code(256);
  // pe_file.read(reinterpret_cast<char *>(code.data()), code.size());

  // // Capstone을 사용해 엔트리포인트부터 디스어셈블
  // std::cout << "\nDisassembling from entry point...\n";
  // disassemble_x86(code, entry_point_va);
  execute_x86(text_content, entry_point_offset_in_text, entry_point_va);

  return 0;
}
