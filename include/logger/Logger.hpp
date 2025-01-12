#pragma once

#include "logger/Stream.hpp"

#include <functional>
#include <string>

namespace logger
{
class Logger
{
public:
    Logger(const std::string& prefix);

    Stream print() const;

private:
    const std::string prefix;
};
} // namespace logger

using OnErrorCallback = std::function<void(const std::string&)>;
