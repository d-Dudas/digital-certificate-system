#include "utils/Check.hpp"
#include "logger/Logger.hpp"

#include <stdexcept>

extern "C"
{
#include <gnutls/gnutls.h>
}

namespace
{
std::string getGnutlsErrorMessage(int result)
{
    return gnutls_strerror(result);
}
} // namespace

namespace utils
{
void gnutlsCheck(int result, const std::string& errorMessage)
{
    if (result != GNUTLS_E_SUCCESS)
    {
        throw std::runtime_error(
            errorMessage + ": " + getGnutlsErrorMessage(result));
    }
}

void gnutlsCheck(int result, const OnErrorCallback& onError)
{
    if (result != GNUTLS_E_SUCCESS)
    {
        onError(getGnutlsErrorMessage(result));
        throw std::runtime_error(getGnutlsErrorMessage(result));
    }
}

void check(int result, const OnErrorCallback& onError)
{
    if (result < 0)
    {
        const std::string message{"No error message available"};
        onError(message);
        throw std::runtime_error(message);
    }
}
} // namespace utils
