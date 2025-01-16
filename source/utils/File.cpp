#include "utils/File.hpp"
#include "logger/Logger.hpp"
#include "utils/Check.hpp"

#include <gnutls/x509.h>
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

gnutls_x509_crt_t importCertificateFromFile(const std::string& path)
{
    gnutls_x509_crt_t certificate;
    gnutls_x509_crt_init(&certificate);
    gnutls_datum_t certificateData{readDatumFromFile(path)};

    gnutlsCheck(
        gnutls_x509_crt_import(
            certificate, &certificateData, GNUTLS_X509_FMT_PEM),
        onErrorCallback("Failed to import certificate"));

    return certificate;
}
} // namespace utils
