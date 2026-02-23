#include "api_context.hpp"
#include <cstdint>
#include <cstring>

#pragma pack(push, 1)
struct MIXERLINE_TARGETA_MOCK {
    uint32_t dwType;
    uint32_t dwDeviceID;
    uint16_t wMid;
    uint16_t wPid;
    uint32_t vDriverVersion;
    char szPname[32];
};

struct MIXERLINEA_MOCK {
    uint32_t cbStruct;
    uint32_t dwDestination;
    uint32_t dwSource;
    uint32_t dwLineID;
    uint32_t fdwLine;
    uint32_t dwUser;
    uint32_t dwComponentType;
    uint32_t cChannels;
    uint32_t cConnections;
    uint32_t cControls;
    char szShortName[16];
    char szName[64];
    MIXERLINE_TARGETA_MOCK Target;
};
#pragma pack(pop)

static void copy_ansi(char* dst, size_t dst_size, const char* src) {
    if (dst == nullptr || dst_size == 0) return;
    std::memset(dst, 0, dst_size);
    if (src == nullptr) return;
    const size_t n = std::strlen(src);
    const size_t to_copy = (n < (dst_size - 1)) ? n : (dst_size - 1);
    std::memcpy(dst, src, to_copy);
}

extern "C" void mock_mixerGetLineInfoA(APIContext* ctx) {
    const uint32_t hmxobj = ctx->get_arg(0);
    const uint32_t pmxl = ctx->get_arg(1);
    const uint32_t fdwInfo = ctx->get_arg(2);
    (void)hmxobj;

    constexpr uint32_t MMSYSERR_NOERROR = 0;
    constexpr uint32_t MMSYSERR_INVALPARAM = 11;
    constexpr uint32_t MIXERR_INVALLINE = 1024;

    constexpr uint32_t MIXER_GETLINEINFOF_DESTINATION = 0x00000000;
    constexpr uint32_t MIXER_GETLINEINFOF_SOURCE = 0x00000001;
    constexpr uint32_t MIXER_GETLINEINFOF_LINEID = 0x00000002;
    constexpr uint32_t MIXER_GETLINEINFOF_COMPONENTTYPE = 0x00000003;
    constexpr uint32_t MIXER_GETLINEINFOF_TARGETTYPE = 0x00000004;
    constexpr uint32_t MIXER_GETLINEINFOF_QUERYMASK = 0x0000000F;

    constexpr uint32_t MIXERLINE_COMPONENTTYPE_DST_SPEAKERS = 0x00000004;
    constexpr uint32_t MIXERLINE_COMPONENTTYPE_SRC_WAVEOUT = 0x00001008;
    constexpr uint32_t MIXERLINE_TARGETTYPE_WAVEOUT = 0x00000001;
    constexpr uint32_t MIXERLINE_LINEF_ACTIVE = 0x00000001;
    constexpr uint32_t MIXERLINE_LINEF_SOURCE = 0x80000000;

    uint32_t result = MMSYSERR_NOERROR;
    MIXERLINEA_MOCK in_line{};
    MIXERLINEA_MOCK out_line{};

    if (pmxl == 0) {
        result = MMSYSERR_INVALPARAM;
    } else {
        uint32_t cbStruct = 0;
        if (uc_mem_read(ctx->uc, pmxl, &cbStruct, sizeof(cbStruct)) != UC_ERR_OK ||
            cbStruct < sizeof(MIXERLINEA_MOCK)) {
            result = MMSYSERR_INVALPARAM;
        } else if (uc_mem_read(ctx->uc, pmxl, &in_line, sizeof(in_line)) != UC_ERR_OK) {
            result = MMSYSERR_INVALPARAM;
        }
    }

    if (result == MMSYSERR_NOERROR) {
        out_line.cbStruct = in_line.cbStruct;

        bool found = false;
        const uint32_t query = fdwInfo & MIXER_GETLINEINFOF_QUERYMASK;

        const auto fill_destination = [&]() {
            out_line.dwDestination = 0;
            out_line.dwSource = 0;
            out_line.dwLineID = 0;
            out_line.fdwLine = MIXERLINE_LINEF_ACTIVE;
            out_line.dwUser = 0;
            out_line.dwComponentType = MIXERLINE_COMPONENTTYPE_DST_SPEAKERS;
            out_line.cChannels = 2;
            out_line.cConnections = 1;
            out_line.cControls = 1;
            copy_ansi(out_line.szShortName, sizeof(out_line.szShortName), "Speakers");
            copy_ansi(out_line.szName, sizeof(out_line.szName), "Speakers (Mock WinMM Mixer)");
            out_line.Target.dwType = MIXERLINE_TARGETTYPE_WAVEOUT;
            out_line.Target.dwDeviceID = 0;
            out_line.Target.wMid = 1;
            out_line.Target.wPid = 0x0100;
            out_line.Target.vDriverVersion = 0x00010000;
            copy_ansi(out_line.Target.szPname, sizeof(out_line.Target.szPname), "Mock Wave Out");
        };

        const auto fill_source = [&]() {
            out_line.dwDestination = 0;
            out_line.dwSource = 0;
            out_line.dwLineID = 1;
            out_line.fdwLine = MIXERLINE_LINEF_ACTIVE | MIXERLINE_LINEF_SOURCE;
            out_line.dwUser = 0;
            out_line.dwComponentType = MIXERLINE_COMPONENTTYPE_SRC_WAVEOUT;
            out_line.cChannels = 2;
            out_line.cConnections = 0;
            out_line.cControls = 1;
            copy_ansi(out_line.szShortName, sizeof(out_line.szShortName), "Wave Out");
            copy_ansi(out_line.szName, sizeof(out_line.szName), "Wave Out (Mock WinMM Source)");
            out_line.Target.dwType = MIXERLINE_TARGETTYPE_WAVEOUT;
            out_line.Target.dwDeviceID = 0;
            out_line.Target.wMid = 1;
            out_line.Target.wPid = 0x0100;
            out_line.Target.vDriverVersion = 0x00010000;
            copy_ansi(out_line.Target.szPname, sizeof(out_line.Target.szPname), "Mock Wave Out");
        };

        switch (query) {
            case MIXER_GETLINEINFOF_DESTINATION:
                if (in_line.dwDestination == 0) {
                    fill_destination();
                    found = true;
                }
                break;
            case MIXER_GETLINEINFOF_SOURCE:
                if (in_line.dwDestination == 0 && in_line.dwSource == 0) {
                    fill_source();
                    found = true;
                }
                break;
            case MIXER_GETLINEINFOF_LINEID:
                if (in_line.dwLineID == 0) {
                    fill_destination();
                    found = true;
                } else if (in_line.dwLineID == 1) {
                    fill_source();
                    found = true;
                }
                break;
            case MIXER_GETLINEINFOF_COMPONENTTYPE:
                if (in_line.dwComponentType == MIXERLINE_COMPONENTTYPE_DST_SPEAKERS) {
                    fill_destination();
                    found = true;
                } else if (in_line.dwComponentType == MIXERLINE_COMPONENTTYPE_SRC_WAVEOUT) {
                    fill_source();
                    found = true;
                }
                break;
            case MIXER_GETLINEINFOF_TARGETTYPE:
                if (in_line.Target.dwType == MIXERLINE_TARGETTYPE_WAVEOUT) {
                    fill_source();
                    found = true;
                }
                break;
            default:
                result = MMSYSERR_INVALPARAM;
                break;
        }

        if (result == MMSYSERR_NOERROR && !found) {
            result = MIXERR_INVALLINE;
        }

        if (result == MMSYSERR_NOERROR) {
            if (uc_mem_write(ctx->uc, pmxl, &out_line, sizeof(out_line)) != UC_ERR_OK) {
                result = MMSYSERR_INVALPARAM;
            }
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