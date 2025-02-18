#include <LIEF/LIEF.hpp>
#include <capstone/capstone.h>
#include <fstream>
#include <iostream>
#include <vector>

void disassemble_x86(const std::vector<uint8_t> &code, uint64_t address) {
  csh handle;
  cs_insn *insn;
  size_t count;

  if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) !=
      CS_ERR_OK) {
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

  uint64_t entry_point_va = binary->entrypoint();
  std::cout << "Entry Point Address (VA): 0x" << std::hex << entry_point_va
            << std::dec << std::endl;

  if (!text_section) {
    std::cerr << "Error: No .text section found!" << std::endl;
    return 1;
  }

  uint64_t entry_offset =
      entry_point_va - text_section->virtual_address() + text_section->offset();
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

  // PE 파일을 읽어서 엔트리포인트 근처의 바이트 가져오기
  std::ifstream pe_file(argv[1], std::ios::binary);
  if (!pe_file) {
    std::cerr << "Error opening PE file!" << std::endl;
    return 1;
  }

  // 엔트리포인트 주변 코드(256바이트) 읽기
  pe_file.seekg(entry_offset);
  std::vector<uint8_t> code(256);
  pe_file.read(reinterpret_cast<char *>(code.data()), code.size());

  // Capstone을 사용해 엔트리포인트부터 디스어셈블
  std::cout << "\nDisassembling from entry point...\n";
  disassemble_x86(code, entry_point_va);

  return 0;
}
