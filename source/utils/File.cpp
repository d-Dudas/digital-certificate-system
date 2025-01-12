#include "utils/File.hpp"
#include "logger/Logger.hpp"
#include "utils/Check.hpp"

#include <stdexcept>

namespace
{
OnErrorCallback onErrorCallback(const std::string& message)
{
    return [message](const std::string& error)
    {
        logger::Logger logger{"File"};
        logger.print().error() << message << " (" << error << ")";
    };
}
} // namespace

namespace utils
{
void writeDatumToFile(const gnutls_datum_t& datum, const std::string& path)
{
    FILE* file = fopen(path.c_str(), "w");
    check(file, onErrorCallback("Failed to open file for writing."));

    if (fwrite(datum.data, 1, datum.size, file) != datum.size)
    {
        throw std::runtime_error("Failed to write data to file.");
    }

    fclose(file);
}

gnutls_datum_t readDatumFromFile(const std::string& path)
{
    gnutls_datum_t datum;
    gnutlsCheck(
        gnutls_load_file(path.c_str(), &datum),
        onErrorCallback("Failed to load file: " + path));

    return datum;
}
} // namespace utils
