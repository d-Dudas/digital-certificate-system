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
    std::ostringstream& withoutPrefix();

private:
    const std::string getPrefix();

    std::ostringstream stream{};
    const std::string prefix;
};
} // namespace logger
