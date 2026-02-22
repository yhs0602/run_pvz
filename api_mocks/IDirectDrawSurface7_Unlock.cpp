#include "api_context.hpp"

extern "C" void mock_IDirectDrawSurface7_Unlock(APIContext* ctx) {
    ctx->set_eax(0); // DD_OK
}
