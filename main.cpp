#include "import_handler.hpp"
#include "virtual_cpu.hpp"
#include "x86.h"
#include <LIEF/Abstract/Binary.hpp>
#include <LIEF/LIEF.hpp>
#include <capstone/capstone.h>
#include <cstdint>
#include <iostream>
#include <span>
#include <vector>

std::map<uint64_t, ImportInfo> api_map;

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

void byte_array_to_string(const uint8_t *bytes, size_t size, std::string &str) {
  for (size_t i = 0; i < size; i++) {
    char buf[4];
    snprintf(buf, sizeof(buf), "%02x ", bytes[i]);
    str += buf;
  }
}

// returns the next eip value
void execute_one_instruction(const csh handle, const cs_insn *insn, CPU &cpu) {
  std::string bytes;
  byte_array_to_string(insn->bytes, insn->size, bytes);
  std::cout << std::hex << insn->address << ": " << std::hex << bytes << " "
            << insn->mnemonic << " " << insn->op_str << std::endl;
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
  case X86_INS_JNE: {
    cpu.execute_jne(insn);
    break;
  }

  default:
    std::cerr << "Unhandled instruction: " << insn->mnemonic << std::endl;
    throw std::runtime_error("Unhandled instruction");
    break;
  }
  // cpu.dump();
  std::cout << "=========================" << std::endl;
}

void execute_x86(const std::span<const uint8_t> &code, uint64_t start_offset,
                 uint64_t entrypoint_va,
                 std::unique_ptr<LIEF::PE::Binary> binary) {
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

  CPU cpu(handle, entrypoint_va);

  // For each section, write the content to memory
  for (const auto &section : binary->sections()) {
    if (section.size() == 0) {
      continue;
    }
    std::cout << "Writing section: " << section.name() << " to memory... at "
              << section.virtual_address() << "("
              << section.virtual_address() +
                     binary->optional_header().imagebase()
              << "-"
              << section.virtual_address() +
                     binary->optional_header().imagebase() + section.size()
              << ")" << std::endl;
    cpu.write_memory_bulk(section.virtual_address() +
                              binary->optional_header().imagebase(),
                          section.content());
  }
  // Fix IAT with imagebase
  for (const auto &import : binary->imports()) {
    for (const auto &entry : import.entries()) {
      // if (entry.iat_value() != 0) {
      std::cout << "Fixing IAT for API: <<" << entry.name() << ">> from <"
                << import.name() << "> of value 0x" << std::hex
                << entry.iat_value() << " at 0x" << entry.iat_address()
                << std::dec << std::endl;
      const uint64_t augmented_iat_value = entry.iat_value() + 0xFF000000;
      api_map[augmented_iat_value] =
          ImportInfo{entry.iat_value(), import.name(), entry.name()};
      if (cpu.read_memory(
              entry.iat_address() + binary->optional_header().imagebase(), 4) !=
          entry.iat_value()) {
        std::cerr << "IAT value mismatch!:" << std::hex
                  << cpu.read_memory(entry.iat_address() +
                                         binary->optional_header().imagebase(),
                                     4)
                  << "!=" << entry.iat_value() << std::dec << std::endl;
        throw std::runtime_error("IAT value mismatch!");
      }
      cpu.write_memory(entry.iat_address() +
                           binary->optional_header().imagebase(),
                       augmented_iat_value, 4);
      // << "Demangled" << entry.demangled_name()
      // << "HintNameRVA" <<  entry.hint_name_rva()
      // << "Hint" <<  entry.hint()
      // << "Data" <<  entry.data()
      // << "Ordinal" <<  entry.ordinal()
      // << "Size" <<  entry.size()
      // << std::dec << std::endl;
      // cpu.write_memory(
      //     entry.iat_value(),
      //     entry.iat_address() + binary->optional_header().imagebase(), 4);
      // }
    }
  }

  std::cout << "Executing from entry point..." << std::endl << std::endl;

  const uint8_t *current_code_ptr = (code.data() + start_offset);
  size_t code_size = code.size();
  uint64_t virtaddr = entrypoint_va;

  int executed = 0;

  std::vector<uint8_t> code_cache(16);
  cpu.eip = entrypoint_va;
  while (true) {
    // check if the current eip is 0xFF......
    if (cpu.eip >= 0xFF000000) {
      std::cout << "IAT call detected!" << std::endl;
      const uint64_t iat_value = cpu.eip;
      auto it = api_map.find(cpu.eip);
      if (it != api_map.end()) {
        std::cout << "API Call: " << it->second.dll_name << "!"
                  << it->second.function_name << std::endl;
      } else {
        std::cerr << "Unknown API Call!" << std::endl;
      }
      break;
    }

    // load code cache (eip, eip+1, ... eip+15)
    for (int i = 0; i < 16; i++) {
      code_cache[i] = cpu.read_memory(cpu.eip + i, 1);
    }
    current_code_ptr = code_cache.data();
    code_size = code_cache.size();
    virtaddr = cpu.eip;
    count =
        cs_disasm_iter(handle, &current_code_ptr, &code_size, &virtaddr, insn);

    if (count == 1) {
      execute_one_instruction(handle, insn, cpu);
      executed += 1;
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
  uint32_t entry_point_va = binary->optional_header().addressof_entrypoint() +
                            binary->optional_header().imagebase();
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
      std::cout << "API: " << entry.name() << " From " << import.name()
                << " IAT: " << std::hex << entry.iat_value() << std::dec
                << std::endl;
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
  auto text_content = text_section->content();
  uint64_t entry_point_offset_in_text = entry_point_va -
                                        text_section->virtual_address() -
                                        binary->optional_header().imagebase();
  std::cout << "Entry Point Offset in .text section: 0x" << std::hex
            << entry_point_offset_in_text << std::dec << std::endl;
  execute_x86(text_content, entry_point_offset_in_text, entry_point_va,
              std::move(binary));

  return 0;
}
