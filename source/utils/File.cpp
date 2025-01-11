#include "utils/File.hpp"

#include <stdexcept>

namespace
{
std::string createErrorMessage(const std::string& message)
{
    return "[utils][File] " + message;
}
} // namespace

namespace utils
{
void writeDatumToFile(const gnutls_datum_t& datum, const std::string& path)
{
    FILE* file = fopen(path.c_str(), "w");
    if (not file)
    {
        throw std::runtime_error(
            createErrorMessage("Failed to open file for writing."));
    }

    if (fwrite(datum.data, 1, datum.size, file) != datum.size)
    {
        throw std::runtime_error(
            createErrorMessage("Failed to write data to file."));
    }

    fclose(file);
}
} // namespace utils
