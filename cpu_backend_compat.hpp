#pragma once

// CPU backend compatibility entrypoint.
// Today this project runs on Unicorn; future backends (e.g. libfexcore)
// should be adapted behind this header first.
#if defined(PVZ_CPU_BACKEND_UNICORN)
#include <unicorn/unicorn.h>
#else
#error "No CPU backend selected."
#endif
