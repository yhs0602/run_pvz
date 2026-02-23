#include "api_context.hpp"
#include <cstdint>
#include <cstring>

#pragma pack(push, 1)
struct MIXERCAPSA_MOCK {
    uint16_t wMid;
    uint16_t wPid;
    uint32_t vDriverVersion;
    char szPname[32];
    uint32_t fdwSupport;
    uint32_t cDestinations;
};
#pragma pack(pop)

extern "C" void mock_mixerGetDevCapsA(APIContext* ctx) {
    const uint32_t uMxId = ctx->get_arg(0);
    const uint32_t pmxcaps = ctx->get_arg(1);
    const uint32_t cbmxcaps = ctx->get_arg(2);

    uint32_t result = 0; // MMSYSERR_NOERROR

    if (pmxcaps == 0 || cbmxcaps == 0) {
        result = 11; // MMSYSERR_INVALPARAM
    } else {
        MIXERCAPSA_MOCK caps{};
        caps.wMid = 1;
        caps.wPid = static_cast<uint16_t>(0x0100u + (uMxId & 0xFFu));
        caps.vDriverVersion = 0x00010000;
        const char* name = "Mock WinMM Mixer";
        const size_t name_len = std::strlen(name);
        const size_t max_copy = sizeof(caps.szPname) - 1;
        const size_t copy_len = (name_len < max_copy) ? name_len : max_copy;
        std::memcpy(caps.szPname, name, copy_len);
        caps.fdwSupport = 0;
        caps.cDestinations = 2;

        const uint32_t write_size =
            (cbmxcaps < static_cast<uint32_t>(sizeof(caps))) ? cbmxcaps : static_cast<uint32_t>(sizeof(caps));

        if (uc_mem_write(ctx->uc, pmxcaps, &caps, write_size) != UC_ERR_OK) {
            result = 11; // MMSYSERR_INVALPARAM
        }
    }

    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 12 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}