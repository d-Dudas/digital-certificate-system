#pragma once

extern "C"
{
#include <gnutls/gnutls.h>
}

#include <string>

namespace utils
{
void writeDatumToFile(const gnutls_datum_t& datum, const std::string& path);
gnutls_datum_t readDatumFromFile(const std::string& path);
} // namespace utils
