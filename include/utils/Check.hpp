#pragma once

#include <string>

namespace utils
{
void check(int result, const std::string& errorMessage);
void check(bool condition, const std::string& errorMessage);
} // namespace utils
