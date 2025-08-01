#pragma once

#if __has_include(<spdlog/spdlog.h>)
#include <spdlog/spdlog.h>
#define KANANLIB_LOGGING_ENABLED
#else
#define SPDLOG_INFO(...)
#define SPDLOG_ERROR(...)
#define SPDLOG_DEBUG(...)
#endif