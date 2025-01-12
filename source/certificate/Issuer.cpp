#include "certificate/Issuer.hpp"
#include "logger/Logger.hpp"
#include "utils/Check.hpp"
#include "utils/File.hpp"

extern "C"
{
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
}

using namespace utils;

namespace certificate
{
Issuer::Issuer()
{
    check(
        gnutls_x509_crt_init(&certificate),
        onErrorCallback("Failed to initialize certificate."));
}

Issuer::~Issuer()
{
    if (certificate)
    {
        gnutls_x509_crt_deinit(certificate);
    }

    if (privateKey)
    {
        gnutls_x509_privkey_deinit(privateKey);
    }
}

OnErrorCallback Issuer::onErrorCallback(const std::string& message)
{
    return [this, message](const std::string& error)
    {
        logger.print().error() << message << " (" << error << ")";
    };
}

void Issuer::setVersion(const int version)
{
    check(
        gnutls_x509_crt_set_version(certificate, version),
        onErrorCallback("Failed to set version."));
}

void Issuer::setSerialNumber(const std::string& serialNumber)
{
    check(
        gnutls_x509_crt_set_serial(
            certificate,
            static_cast<const void*>(serialNumber.data()),
            serialNumber.size()),
        onErrorCallback("Failed to set serial number."));
}

void Issuer::setActivationTime(
    std::chrono::system_clock::time_point activationTime)
{
    const auto activationTimeT =
        std::chrono::system_clock::to_time_t(activationTime);
    check(
        gnutls_x509_crt_set_activation_time(certificate, activationTimeT),
        onErrorCallback("Failed to set activation time."));
}

void Issuer::setExpirationTime(
    std::chrono::system_clock::time_point expirationTime)
{
    const auto expirationTimeT =
        std::chrono::system_clock::to_time_t(expirationTime);
    check(
        gnutls_x509_crt_set_expiration_time(certificate, expirationTimeT),
        onErrorCallback("Failed to set expiration time."));
}

void Issuer::setDistinguishedName(const std::string& distinguishedName)
{
    check(
        gnutls_x509_crt_set_dn(certificate, distinguishedName.c_str(), 0),
        onErrorCallback("Failed to set distinguished name."));
}

void Issuer::sign(
    std::string pathToRootCertificate,
    const std::string pathToRootPrivateKey)
{
    if (not privateKey)
    {
        setPrivateKey(pathToRootPrivateKey);
    }

    gnutls_x509_crt_t rootCertificate{};
    gnutls_x509_privkey_t rootPrivateKey{};
    gnutls_datum_t fileData;

    check(
        gnutls_x509_crt_init(&rootCertificate),
        onErrorCallback("Failed to initialize root certificate."));

    check(
        gnutls_x509_privkey_init(&rootPrivateKey),
        onErrorCallback("Failed to initialize root private key."));

    check(
        gnutls_load_file(pathToRootCertificate.c_str(), &fileData),
        onErrorCallback("Failed to import root certificate."));

    check(
        gnutls_x509_crt_import(rootCertificate, &fileData, GNUTLS_X509_FMT_PEM),
        onErrorCallback("Failed to import root certificate."));

    gnutls_free(fileData.data);

    check(
        gnutls_load_file(pathToRootPrivateKey.c_str(), &fileData),
        onErrorCallback("Failed to import root private key."));

    check(
        gnutls_x509_privkey_import(
            rootPrivateKey, &fileData, GNUTLS_X509_FMT_PEM),
        onErrorCallback("Failed to import root private key."));

    gnutls_free(fileData.data);

    check(
        gnutls_x509_crt_set_key_usage(
            certificate,
            GNUTLS_KEY_DATA_ENCIPHERMENT | GNUTLS_KEY_DIGITAL_SIGNATURE),
        onErrorCallback("Failed to set key usage."));

    check(
        gnutls_x509_crt_sign(certificate, rootCertificate, rootPrivateKey),
        onErrorCallback("Failed to sign certificate."));

    gnutls_x509_crt_deinit(rootCertificate);
    gnutls_x509_privkey_deinit(rootPrivateKey);
}

void Issuer::sign()
{
    if (not privateKey)
    {
        generateAndSetPrivateKey();
    }

    check(
        gnutls_x509_crt_set_key_usage(
            certificate, GNUTLS_KEY_KEY_CERT_SIGN | GNUTLS_KEY_CRL_SIGN),
        onErrorCallback("Failed to set key usage."));

    check(
        gnutls_x509_crt_set_basic_constraints(certificate, 1, -1),
        onErrorCallback(
            "Failed to set basic constraints for root certificate."));

    check(
        gnutls_x509_crt_sign(certificate, certificate, privateKey),
        onErrorCallback("Failed to sign certificate."));
}

void Issuer::exportCertificateToFile(const std::string& certificatePath)
{
    gnutls_datum_t certificateData;
    check(
        gnutls_x509_crt_export2(
            certificate, GNUTLS_X509_FMT_PEM, &certificateData),
        onErrorCallback("Failed to export certificate."));

    writeDatumToFile(certificateData, certificatePath);
    gnutls_free(certificateData.data);

    logger.print().info() << "Certificate exported to " << certificatePath;
}

void Issuer::exportPrivateKeyToFile(const std::string& privateKeyPath)
{
    gnutls_datum_t privateKeyData;
    check(
        gnutls_x509_privkey_export2(
            privateKey, GNUTLS_X509_FMT_PEM, &privateKeyData),
        onErrorCallback("Failed to export private key."));

    writeDatumToFile(privateKeyData, privateKeyPath);
    gnutls_free(privateKeyData.data);

    logger.print().info() << "Private key exported to " << privateKeyPath;
}

void Issuer::generateAndSetPrivateKey()
{
    check(
        gnutls_x509_privkey_init(&privateKey),
        onErrorCallback("Failed to initialize private key."));

    check(
        gnutls_x509_privkey_generate(privateKey, GNUTLS_PK_RSA, 2048, 0),
        onErrorCallback("Failed to generate private key."));

    check(
        gnutls_x509_crt_set_key(certificate, privateKey),
        onErrorCallback("Failed to set private key."));

    logger.print().info() << "Private key generated.";
}

void Issuer::setPrivateKey(const std::string& privateKeyPath)
{
    gnutls_datum_t privateKeyData;
    check(
        gnutls_load_file(privateKeyPath.c_str(), &privateKeyData),
        onErrorCallback("Failed to load private key from file."));

    check(
        gnutls_x509_privkey_init(&privateKey),
        onErrorCallback("Failed to initialize private key."));

    check(
        gnutls_x509_privkey_import(
            privateKey, &privateKeyData, GNUTLS_X509_FMT_PEM),
        onErrorCallback("Failed to import private key."));

    check(
        gnutls_x509_crt_set_key(certificate, privateKey),
        onErrorCallback("Failed to set private key."));

    gnutls_free(privateKeyData.data);
}
} // namespace certificate
