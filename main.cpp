#include "pe_loader.hpp"
#include "windows_env.hpp"
#include "api_handler.hpp"
#include <capstone/capstone.h>
#include <iostream>
#include <set>

using namespace std;

// Capstone handle for LVA
csh cs_handle;

const char* reg_name_str(uint32_t reg_id) {
    const char* name = cs_reg_name(cs_handle, reg_id);
    return name ? name : "unknown";
}

// Basic Block Hook for Capstone Live-Variable Analysis (LVA)
void hook_block_lva(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    if (address >= DummyAPIHandler::FAKE_API_BASE) {
        return; // Do not trace dummy API blocks
    }

    cout << "\n--- Basic Block Hook: 0x" << hex << address << ", size: " << dec << size << " ---" << endl;
    
    std::vector<uint8_t> code(size);
    uc_err err = uc_mem_read(uc, address, code.data(), size);
    if (err) {
        cout << "Failed to read memory at 0x" << hex << address << ": " << err << endl;
        return;
    }

    cs_insn *insn;
    size_t count = cs_disasm(cs_handle, code.data(), size, address, 0, &insn);
    
    set<uint32_t> live_in;
    set<uint32_t> live_out;

    cout << "Disassembly:" << endl;
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            cout << "  0x" << hex << insn[i].address << ":\t" << insn[i].mnemonic << "\t" << insn[i].op_str << endl;
            
            cs_regs regs_read, regs_write;
            uint8_t read_count, write_count;
            
            if (cs_regs_access(cs_handle, &insn[i], regs_read, &read_count, regs_write, &write_count) == CS_ERR_OK) {
                for (uint8_t j = 0; j < read_count; j++) {
                    if (live_out.find(regs_read[j]) == live_out.end()) {
                        live_in.insert(regs_read[j]);
                    }
                }
                for (uint8_t j = 0; j < write_count; j++) {
                    live_out.insert(regs_write[j]);
                }
            }
        }
        cs_free(insn, count);
    } else {
        cout << "Capstone error during disassembly." << endl;
    }

    cout << "Live-In : ";
    if (live_in.empty()) cout << "(None)";
    else for (auto r : live_in) cout << reg_name_str(r) << ", ";
    cout << endl;

    cout << "Live-Out: ";
    if (live_out.empty()) cout << "(None)";
    else for (auto r : live_out) cout << reg_name_str(r) << ", ";
    cout << endl;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <PE file>" << endl;
        return 1;
    }

    // Initialize Capstone (DETAIL mode ON for LVA)
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle) != CS_ERR_OK) {
        cerr << "Failed to initialize Capstone!" << endl;
        return 1;
    }
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    // Initialize Unicorn
    uc_engine *uc;
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        cerr << "Failed on uc_open() with error: " << err << endl;
        return 1;
    }

    try {
        // Initialize Modules
        PEModule pe_module(argv[1]);
        WindowsEnvironment env(uc);
        DummyAPIHandler api_handler(uc);

        // Map and Load
        pe_module.map_into(uc);
        pe_module.resolve_imports(uc, api_handler);
        env.setup_system();

        // Attach Basic Block LVA hook
        uc_hook hook1;
        uc_hook_add(uc, &hook1, UC_HOOK_BLOCK, (void*)hook_block_lva, nullptr, 1, 0);

        // Start Emulation
        cout << "\n[*] Starting C++ Engine Emulation at 0x" << hex << pe_module.entry_point << "...\n";
        err = uc_emu_start(uc, pe_module.entry_point, 0, 0, 0);
        
        if (err) {
            uint32_t pc;
            uc_reg_read(uc, UC_X86_REG_EIP, &pc);
            cout << "\n[!] Emulation stopped due to error: " << uc_strerror(err) << " (Code: " << err << ")\n";
            cout << "[!] EIP = 0x" << hex << pc << endl;
        }

    } catch (const exception& e) {
        cerr << "Exception caught: " << e.what() << endl;
    }

    uc_close(uc);
    cs_close(&cs_handle);
    return 0;
}
