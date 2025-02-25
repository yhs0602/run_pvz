#include "virtual_cpu.hpp"
#include "x86.h"
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

// returns the next eip value
void execute_one_instruction(const csh handle, const cs_insn *insn, CPU &cpu) {
  std::cout << std::hex << insn->address << ": " << insn->mnemonic << " "
            << insn->op_str << std::endl;
  // assert that cpu eip is same as insn address
  assert(cpu.eip == insn->address);
  // Step the CPU
  cpu.eip = cpu.eip + insn->size;

  switch (insn->id) {
  case X86_INS_CALL: {
    cpu.execute_call(insn);
    break;
  }
  case X86_INS_RET:
    cpu.execute_return();
    break;
  case X86_INS_JMP: {
    cpu.execute_jmp(insn);
    break;
  }
  case X86_INS_PUSH: {
    cpu.execute_push(insn);
    break;
  }
  case X86_INS_POP: {
    cpu.execute_pop(insn);
    break;
  }
  case X86_INS_MOV: {
    cpu.execute_mov(insn);
    break;
  }
  case X86_INS_LEA: {
    cpu.execute_lea(insn);
    break;
  }
  case X86_INS_SUB: {
    cpu.execute_sub(insn);
    break;
  }
  case X86_INS_ADD: {
    cpu.execute_add(insn);
    break;
  }
  case X86_INS_AND: {
    cpu.execute_and(insn);
    break;
  }
  case X86_INS_XOR: {
    cpu.execute_xor(insn);
    break;
  }
  case X86_INS_OR: {
    cpu.execute_or(insn);
    break;
  }
  case X86_INS_TEST: {
    cpu.execute_test(insn);
    break;
  }
  case X86_INS_JE: {
    cpu.execute_je(insn);
    break;
  }
  case X86_INS_CMP: {
    cpu.execute_cmp(insn);
    break;
  }

  default:
    std::cerr << "Unhandled instruction: " << insn->mnemonic << std::endl;
    throw std::runtime_error("Unhandled instruction");
    break;
  }
  cpu.dump();
  std::cout << "=========================" << std::endl;
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

  CPU cpu(handle, address);
  std::cout << "Executing from entry point..." << std::endl << std::endl;

  const uint8_t *current_code_ptr = (code.data() + start_offset);
  size_t code_size = code.size();
  uint64_t virtaddr = address;

  int executed = 0;
  cpu.eip = address;
  while (true) {
    count =
        cs_disasm_iter(handle, &current_code_ptr, &code_size, &virtaddr, insn);
    if (count == 1) {
      execute_one_instruction(handle, insn, cpu);
      executed += 1;
      // calculate the new current_code_ptr
      current_code_ptr = code.data() + (cpu.eip - address);
      virtaddr = cpu.eip;
      if (executed == 40) {
        break;
      }
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
  binary->import_section();
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

  // std::cout << binary->section_from_rva(0x699fe8) << std::endl;
  // Parse IAT
  for (auto &import : binary->imported_functions()) {
    std::cout << "Imported Function: " << import << std::endl;
  }
  for (auto &library : binary->imported_libraries()) {
    std::cout << "Imported Library: " << library << std::endl;
  }
  // data directories
  for (const auto &data_directory : binary->data_directories()) {
    std::cout << "Data Directory: " << data_directory << std::endl;
  }

  for (const auto &import : binary->imports()) {
    for (const auto &entry : import.entries()) {
      if (entry.iat_value() == 0x699FE8) {
        std::cout << "0x699FE8 is used for API: " << entry.name() << std::endl;
      } else {
        std::cout << "API: " << entry.name() << " IAT: " << std::hex
                  << entry.iat_value() << std::dec << std::endl;
      }
    }
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
