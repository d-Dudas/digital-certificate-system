#include <Check.hpp>

#include <stdexcept>
#include <gnutls/gnutls.h>

namespace
{
std::string getGnutlsErrorMessage(int result)
{
    return gnutls_strerror(result);
}
} // namespace

void check(int result, const std::string& errorMessage)
{
    if (result != GNUTLS_E_SUCCESS)
    {
        throw std::runtime_error(
            errorMessage + ": " + getGnutlsErrorMessage(result));
    }
}

void check(bool condition, const std::string& errorMessage)
{
    if (not condition)
    {
        throw std::runtime_error(errorMessage);
    }
}
