#pragma once

#include <string>
#include <chrono>

extern "C"
{
#include <gnutls/gnutls.h>
}

class RootCertificateGenerator
{
public:
    RootCertificateGenerator();
    ~RootCertificateGenerator();

    void readPrivateKey(const std::string& privateKeyFilePath);
    void setVersion(const int version);
    void setSerialNumber(const std::string& serialNumber);
    void setActivationTime(std::chrono::system_clock::time_point activationTime);
    void setExpirationTime(std::chrono::system_clock::time_point expirationTime);
    void setDistinguishedName(const std::string& distinguishedName);
    void sign();
    void saveToFile(const std::string& certificateFilePath);
private:
    gnutls_x509_crt_t certificate;
    gnutls_x509_privkey_t privateKey;
};
