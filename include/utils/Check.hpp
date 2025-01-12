#pragma once

#include <string>
#include "logger/Logger.hpp"

namespace utils
{
void gnutlsCheck(int result, const OnErrorCallback& onError);
void check(int result, const OnErrorCallback& onError);

template <typename T>
void check(T* pointer, const OnErrorCallback& onError)
{
    if (not pointer)
    {
        const std::string message{"Null pointer"};
        onError(message);
        throw std::runtime_error(message);
    }
}
} // namespace utils
