#pragma once

// CPU backend compatibility entrypoint.
// We keep Unicorn ABI types (`uc_err`, register ids, hook ids) as the
// stable API surface across backend implementations.
#if defined(PVZ_CPU_BACKEND_UNICORN) || defined(PVZ_CPU_BACKEND_FEXCORE)
#include <unicorn/unicorn.h>
#else
#error "No CPU backend selected."
#endif
