#pragma once

#include <string>
#include <chrono>

extern "C"
{
#include <gnutls/gnutls.h>
}

class CertificateIssuer
{
public:
    CertificateIssuer();
    ~CertificateIssuer();

    void setVersion(const int version);
    void setPrivateKey(const std::string& privateKeyFilePath);
    void setSerialNumber(const std::string& serialNumber);
    void setActivationTime(
        std::chrono::system_clock::time_point activationTime);
    void setExpirationTime(
        std::chrono::system_clock::time_point expirationTime);
    void setDistinguishedName(const std::string& distinguishedName);

    // set key usage
    // set basic constraints
    // set CA status
    // set key purpose OID
    // set subject alternative name

    void sign(
        const std::string pathToRootCertificate,
        const std::string pathToRootPrivateKey);
    void sign();

    void exportCertificateToFile(const std::string& path) const;
    void exportPrivateKeyToFile(const std::string& path) const;

private:
    void generateAndSetPrivateKey();

    gnutls_x509_crt_t certificate{};
    gnutls_x509_privkey_t privateKey{};
};
