#pragma once

#include <sstream>
#include <string>

namespace logger
{
class Stream
{
public:
    Stream(const std::string& prefix);
    Stream(const Stream&);
    ~Stream();

    std::ostringstream& error();
    std::ostringstream& info();
    std::ostringstream& warning();

private:
    std::ostringstream stream{};
};
} // namespace logger
