#include "logger/Logger.hpp"
#include "logger/Stream.hpp"

namespace logger
{
Logger::Logger(const std::string& prefix)
: prefix{prefix}
{
}

Stream Logger::print() const
{
    return Stream{prefix};
}
} // namespace logger
