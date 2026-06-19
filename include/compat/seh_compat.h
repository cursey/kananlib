// Compatibility redirect. The structured-exception wrappers now live in the
// portable header utility/Seh.hpp (named KANANLIB_SEH_TRY / KANANLIB_SEH_EXCEPT
// so they don't collide with libstdc++'s internal __try/__catch macros).
#pragma once
#include <utility/Seh.hpp>
