#pragma once

#include <chrono>
#include <gnutls/x509.h>
#include <string>
#include "logger/Logger.hpp"

extern "C"
{
#include <gnutls/gnutls.h>
}

namespace certificate
{
class Revocator
{
public:
    Revocator(
        const std::string& pathToRootCertificate,
        const std::string& pathToRootPrivateKey);
    ~Revocator();

    void revokeCertificate(
        const std::string& serialNumber,
        std::chrono::system_clock::time_point revocationTime);
    bool isCertificateRevoked(const std::string& serialNumber) const;

    void exportCRLToFile(const std::string& path) const;

    OnErrorCallback onErrorCallback(const std::string& message) const;

private:
    void readAndSetRootCertificate(const std::string& path);
    void readAndSetRootPrivateKey(const std::string& path);

    logger::Logger logger{"Revocator"};
    gnutls_x509_crl_t crl;
    gnutls_x509_crt_t rootCertificate;
    gnutls_x509_privkey_t rootPrivateKey;
};
} // namespace certificate
