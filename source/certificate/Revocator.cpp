#include "certificate/Revocator.hpp"
#include "Check.hpp"
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

namespace
{
std::string createErrorMessage(const std::string& message)
{
    return "[certificate][Revocator] " + message;
}
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

    time_t nextUpdate = time(nullptr) + 30 * 24 * 60 * 60; // 30 days from now
    check(
        gnutls_x509_crl_set_next_update(crl, nextUpdate),
        createErrorMessage("Failed to set CRL next update time."));

    time_t thisUpdate = time(nullptr);
    check(
        gnutls_x509_crl_set_this_update(crl, thisUpdate),
        createErrorMessage("Failed to set CRL this update time."));

    check(
        gnutls_x509_crl_set_version(crl, 3),
        createErrorMessage("Failed to set CRL version."));
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

void Revocator::readAndSetRootCertificate(const std::string& path)
{
    gnutls_datum_t fileData{utils::readDatumFromFile(path)};
    check(
        gnutls_x509_crt_init(&rootCertificate),
        createErrorMessage("Failed to initialize root certificate."));
    check(
        gnutls_x509_crt_import(rootCertificate, &fileData, GNUTLS_X509_FMT_PEM),
        createErrorMessage("Failed to import root certificate."));
    gnutls_free(fileData.data);
}

void Revocator::readAndSetRootPrivateKey(const std::string& path)
{
    gnutls_datum_t fileData{utils::readDatumFromFile(path)};
    check(
        gnutls_x509_privkey_init(&rootPrivateKey),
        createErrorMessage("Failed to initialize root private key."));
    check(
        gnutls_x509_privkey_import(
            rootPrivateKey, &fileData, GNUTLS_X509_FMT_PEM),
        createErrorMessage("Failed to import root private key."));
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
        createErrorMessage("Failed to add revoked certificate to CRL."));
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
            createErrorMessage("Failed to get revoked certificate data."));

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
        createErrorMessage("Failed to sign CRL."));

    gnutls_datum_t crlData;
    check(
        gnutls_x509_crl_export2(crl, GNUTLS_X509_FMT_PEM, &crlData),
        createErrorMessage("Failed to export CRL."));
    utils::writeDatumToFile(crlData, path);
    gnutls_free(crlData.data);
}
} // namespace certificate
