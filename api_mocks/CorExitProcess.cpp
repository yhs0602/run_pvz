#include "api_context.hpp"

extern "C" void mock_CorExitProcess(APIContext* ctx) {
    const uint32_t exit_code = static_cast<uint32_t>(ctx->get_arg(0));

    ctx->global_state["ProcessTerminated"] = 1;
    ctx->global_state["ProcessExitCode"] = exit_code;

    ctx->set_eax(0);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 4 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}