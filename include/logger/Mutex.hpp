#pragma once

#include <mutex>

namespace logger
{
static std::mutex mutex{};
} // namespace logger
