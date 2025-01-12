#include "logger/Stream.hpp"
#include "logger/Mutex.hpp"

#include <iomanip>
#include <iostream>

namespace
{
std::string timestamp()
{
    auto now{std::chrono::system_clock::now()};
    auto time{std::chrono::system_clock::to_time_t(now)};

    std::stringstream stream{};
    stream << std::put_time(std::localtime(&time), "[%Y-%m-%d %H:%M:%S]");

    return stream.str();
}
} // namespace

namespace logger
{
Stream::Stream(const std::string& prefix)
{
    stream << timestamp() << "[" << prefix << "]";
}

Stream::Stream(const Stream& other)
{
    stream << other.stream.str();
}

Stream::~Stream()
{
    std::lock_guard<std::mutex> lock(mutex);

    std::cout << stream.str() << std::endl;
}

std::ostringstream& Stream::error()
{
    stream << "[ERR] ";
    return stream;
}

std::ostringstream& Stream::info()
{
    stream << "[INF] ";
    return stream;
}

std::ostringstream& Stream::warning()
{
    stream << "[WRN] ";
    return stream;
}
} // namespace logger
