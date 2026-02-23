#include "virtual_cpu.hpp"
#include <cstdint>
#include <span>

typedef struct _PEB_LDR_DATA {
  uint8_t Reserved1[8];
  void *Reserved2[3];
  // InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// GDT selector
// bit 0-1: Requested Privilege Level (RPL)
// bit 2: Table Indicator (TI): 0 = GDT, 1 = LDT
// bit 3-15: Index
// If FS == 0x0038
// (0b0000_0000_0011_1000)
// RPL = 00, TI = 0, Index = 0x38
// Entry size of GDT is 8 bytes
// 0x38 / 8 = 0x7; 7th entry
// 0; NULL
// 1; Kernel Code
// 2; Kernel Data
// 3; User Code
// 4; User Data
// 5; TSS: Task State Segment
// 6; PEB: Process Environment Block; 0x7FFD8000
// 7; TEB: Thread Environment Block; 0x7FFDF000

// In 16 bit mode: 16 * segment register + offset
// In 32 bit mode: segment register is an offset of GDT entry in bytes; 0x38:
// 7th entry of GDT table.

// Translate GDT selector to base address
uint32_t CPU::translate_gdt(short segment_value) {
  const uint32_t gdt_index = segment_value / 8;
  switch (gdt_index) {
  case 0:
    throw std::runtime_error("NULL segment register!");
  case 1:
    throw std::runtime_error("Kernel Code segment register!");
  case 2:
    throw std::runtime_error("Kernel Data segment register!");
  case 3:
    throw std::runtime_error("User Code segment register!");
  case 4:
    throw std::runtime_error("User Data segment register!");
  case 5:
    throw std::runtime_error("TSS segment register!");
  case 6:
    return PEB_BASE;
  case 7:
    return TEB_BASE;
  }
  throw std::runtime_error("Invalid segment register!");
}

void CPU::initialize_teb() {
  // TEB: Thread Environment Block
  // FS:[0] = TEB
  // 0x7FFDF000: TEB struct
  // 0x7FFD8000: PEB struct
  write_memory(TEB_BASE, TEB_BASE, 4);                       // Self pointer
  write_memory(TEB_BASE + 0x04, STACK_BASE, 4);              // Stack base
  write_memory(TEB_BASE + 0x08, STACK_BASE - STACK_SIZE, 4); // Stack limit
  write_memory(TEB_BASE + 0x18, 0x1234, 4);                  // Thread ID
  write_memory(TEB_BASE + 0x30, PEB_BASE, 4);                // PEB Pointer
  write_memory(TEB_BASE + 0x34, 0, 4);                       // LastError

  // PEB: Process Environment Block
  write_memory(PEB_BASE, 0, 1);        // Being Debugged
  write_memory(PEB_BASE + 0x0C, 0, 4); // Ldr (PEB_LDR_DATA)*
  write_memory(PEB_BASE + 0x18, 0,
               4); // ProcessParameters (RTL_USER_PROCESS_PARAMETERS)*
  write_memory(PEB_BASE + 0x3C, 0, 4); // Session ID
}

uint64_t CPU::read_memory(uint32_t address, int size) {
  int page = address / PAGE_SIZE;
  int offset = address % PAGE_SIZE;
  if (offset % size != 0) {
    throw std::runtime_error("Unaligned memory access!");
  }
  if (memory.find(page) == memory.end()) {
    std::string error_message =
        "Invalid memory page! Reading from unmapped memory!";
    // Add hex address to the error message
    error_message += " Address: 0x" + std::format("{:x}", address) + "\n";
    // for (const auto &[page, data] : memory) {
    //   error_message += "Allocated Page: " + std::format("{:x}\n", page);
    // }
    // Add page number to the error message
    error_message += " Page: " + std::to_string(page);
    throw std::runtime_error(error_message);
    std::cerr << error_message << std::endl;
    return 0;
  }
  // std::cout << "Reading from page: " << page << " offset: " << offset
  //           << std::endl;
  switch (size) {
  case 1:
    return static_cast<uint64_t>(memory[page][offset]);
  case 2:
    return static_cast<uint64_t>(memory[page][offset]) |
           (static_cast<uint64_t>(memory[page][offset + 1]) << 8);
  case 4:
    return static_cast<uint64_t>(memory[page][offset]) |
           (static_cast<uint64_t>(memory[page][offset + 1]) << 8) |
           (static_cast<uint64_t>(memory[page][offset + 2]) << 16) |
           (static_cast<uint64_t>(memory[page][offset + 3]) << 24);
  case 8:
    return static_cast<uint64_t>(memory[page][offset]) |
           (static_cast<uint64_t>(memory[page][offset + 1]) << 8) |
           (static_cast<uint64_t>(memory[page][offset + 2]) << 16) |
           (static_cast<uint64_t>(memory[page][offset + 3]) << 24) |
           (static_cast<uint64_t>(memory[page][offset + 4]) << 32) |
           (static_cast<uint64_t>(memory[page][offset + 5]) << 40) |
           (static_cast<uint64_t>(memory[page][offset + 6]) << 48) |
           (static_cast<uint64_t>(memory[page][offset + 7]) << 56);
  default:
    throw std::runtime_error("Invalid memory read size!");
  }
}

void CPU::write_memory_bulk(uint32_t address,
                            const std::span<const uint8_t> &data) {
  const uint32_t size = data.size();
  // calculate the start page
  const uint32_t start_page = address / PAGE_SIZE;
  const uint32_t start_offset = address % PAGE_SIZE;
  // calculate the end page
  const uint32_t end_page = (address + size - 1) / PAGE_SIZE;

  uint32_t bytes_written = 0;
  uint32_t remaining_bytes = size;
  uint32_t current_address = address;

  for (uint32_t current_page = start_page; current_page <= end_page;
       ++current_page) {
    // Ensure the page is allocated
    if (memory.find(current_page) == memory.end()) {
      memory[current_page] = std::vector<uint8_t>(PAGE_SIZE);
    }

    uint32_t current_offset = current_address % PAGE_SIZE;
    uint32_t bytes_to_copy =
        std::min(PAGE_SIZE - current_offset, remaining_bytes);

    // Copy the data chunk to the current page
    std::memcpy(&memory[current_page][current_offset], &data[bytes_written],
                bytes_to_copy);

    // Update counters
    bytes_written += bytes_to_copy;
    remaining_bytes -= bytes_to_copy;
    current_address += bytes_to_copy;
  }
}

void CPU::write_memory(uint32_t address, int value, int size) {
  // 4KB page
  int page = address / PAGE_SIZE;
  int offset = address % PAGE_SIZE;
  // assert that the offset is aligned
  if (offset % size != 0) {
    throw std::runtime_error("Unaligned memory access!");
  }
  if (memory.find(page) == memory.end()) {
    memory[page] = std::vector<uint8_t>(PAGE_SIZE);
  }
  // write memory by 1, 2, 4 bytes
  switch (size) {
  case 1:
    memory[page][offset] = value & 0xFF;
    break;
  case 2:
    memory[page][offset] = value & 0xFF;
    memory[page][offset + 1] = (value >> 8) & 0xFF;
    break;
  case 4:
    memory[page][offset] = value & 0xFF;
    memory[page][offset + 1] = (value >> 8) & 0xFF;
    memory[page][offset + 2] = (value >> 16) & 0xFF;
    memory[page][offset + 3] = (value >> 24) & 0xFF;
    break;
  default:
    throw std::runtime_error("Invalid memory write size!");
  }
  std::cout << "Writing to page: " << std::hex << page << " offset: " << offset
            << " value: " << value << std::endl;
}

uint32_t CPU::calculate_operand_memory(const x86_op_mem &operand) {
  std::cout << "Reading memory operand" << std::endl;
  std::cout << "Scale: " << operand.scale << std::endl;
  std::cout << "Displacement: " << operand.disp << std::endl;
  const uint32_t disp = operand.disp;
  uint32_t base_addr = 0;
  uint32_t index_addr = 0;
  uint32_t segment_base_addr = 0;
  if (operand.segment != X86_REG_INVALID) {
    std::cout << "Segment: " << cs_reg_name(handle, operand.segment)
              << std::endl;
    // Segment register should be translated using GDT
    short segment_value = read_register(operand.segment);
    segment_base_addr = translate_gdt(segment_value);
  }
  if (operand.base != X86_REG_INVALID) {
    std::cout << "Base: " << cs_reg_name(handle, operand.base) << std::endl;
    base_addr = read_register(operand.base);
  }
  if (operand.index != X86_REG_INVALID) {
    std::cout << "Index: " << cs_reg_name(handle, operand.index) << std::endl;
    const uint32_t index_addr = read_register(operand.index) * operand.scale;
  }
  const uint32_t effective_addr =
      segment_base_addr + base_addr + index_addr + disp;
  return effective_addr;
}