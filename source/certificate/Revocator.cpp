#include "certificate/Revocator.hpp"
#include "utils/Check.hpp"
#include "utils/File.hpp"

#include <cstddef>
#include <cstring>
#include <ctime>
#include <gnutls/gnutls.h>
#include <vector>

extern "C"
{
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include <gnutls/x509-ext.h>
}

using namespace utils;

namespace
{
constexpr time_t thirtyDays{30 * 24 * 60 * 60};
auto now{[]()
         {
             return std::chrono::system_clock::to_time_t(
                 std::chrono::system_clock::now());
         }};
} // namespace

namespace certificate
{
Revocator::Revocator(
    const std::string& pathToRootCertificate,
    const std::string& pathToRootPrivateKey)
{
    gnutls_x509_crl_init(&crl);
    readAndSetRootCertificate(pathToRootCertificate);
    readAndSetRootPrivateKey(pathToRootPrivateKey);

    check(
        gnutls_x509_crl_set_next_update(crl, thirtyDays),
        onErrorCallback("Failed to set CRL next update time."));

    check(
        gnutls_x509_crl_set_this_update(crl, now()),
        onErrorCallback("Failed to set CRL this update time."));

    check(
        gnutls_x509_crl_set_version(crl, 3),
        onErrorCallback("Failed to set CRL version."));
}

Revocator::~Revocator()
{
    if (crl)
    {
        gnutls_x509_crl_deinit(crl);
    }

    if (rootCertificate)
    {
        gnutls_x509_crt_deinit(rootCertificate);
    }

    if (rootPrivateKey)
    {
        gnutls_x509_privkey_deinit(rootPrivateKey);
    }
}

OnErrorCallback Revocator::onErrorCallback(const std::string& message) const
{
    return [this, message](const std::string& error)
    {
        logger.print().error() << message << " (" << error << ")";
    };
}

void Revocator::readAndSetRootCertificate(const std::string& path)
{
    gnutls_datum_t fileData{readDatumFromFile(path)};
    check(
        gnutls_x509_crt_init(&rootCertificate),
        onErrorCallback("Failed to initialize root certificate."));
    check(
        gnutls_x509_crt_import(rootCertificate, &fileData, GNUTLS_X509_FMT_PEM),
        onErrorCallback("Failed to import root certificate."));
    gnutls_free(fileData.data);
}

void Revocator::readAndSetRootPrivateKey(const std::string& path)
{
    gnutls_datum_t fileData{readDatumFromFile(path)};
    check(
        gnutls_x509_privkey_init(&rootPrivateKey),
        onErrorCallback("Failed to initialize root private key."));
    check(
        gnutls_x509_privkey_import(
            rootPrivateKey, &fileData, GNUTLS_X509_FMT_PEM),
        onErrorCallback("Failed to import root private key."));
    gnutls_free(fileData.data);
}

void Revocator::revokeCertificate(
    const std::string& serialNumber,
    std::chrono::system_clock::time_point revocationTime)
{
    gnutls_datum_t serialData;
    serialData.data = (unsigned char*)serialNumber.data();
    serialData.size = serialNumber.size();

    const auto revocationTimeT =
        std::chrono::system_clock::to_time_t(revocationTime);

    check(
        gnutls_x509_crl_set_crt_serial(
            crl, serialData.data, serialData.size, revocationTimeT),
        onErrorCallback("Failed to add revoked certificate to CRL."));

    logger.print().info() << "Certificate with serial number " << serialNumber
                          << " revoked.";
}

bool Revocator::isCertificateRevoked(const std::string& serialNumber) const
{
    auto revokedCount = gnutls_x509_crl_get_certificate_count(crl);
    for (int i = 0; i < revokedCount; ++i)
    {
        unsigned char serialData[64];
        size_t serialSize = sizeof(serialData);
        time_t revocationTime;

        check(
            gnutls_x509_crl_get_crt_serial(
                crl, i, serialData, &serialSize, &revocationTime),
            onErrorCallback("Failed to get revoked certificate data."));

        std::vector<unsigned char> serialNumberData{
            serialNumber.begin(), serialNumber.end()};

        if (serialSize == serialNumberData.size()
            and std::memcmp(serialData, serialNumberData.data(), serialSize)
                    == 0)
        {
            return true;
        }
    }

    return false;
}

void Revocator::exportCRLToFile(const std::string& path) const
{
    check(
        gnutls_x509_crl_sign(crl, rootCertificate, rootPrivateKey),
        onErrorCallback("Failed to sign CRL."));

    gnutls_datum_t crlData;
    check(
        gnutls_x509_crl_export2(crl, GNUTLS_X509_FMT_PEM, &crlData),
        onErrorCallback("Failed to export CRL."));
    writeDatumToFile(crlData, path);
    gnutls_free(crlData.data);

    logger.print().info() << "CRL exported to " << path;
}
} // namespace certificate
