#include <RootCertificateGenerator.hpp>
#include <Check.hpp>

#include <iostream>

extern "C"
{
#include <gnutls/x509.h>
}

namespace
{
const std::string rootCertificateGeneratorLogPrefix{
    "[RootCertificateGenerator] "};

std::string createErrorMessage(const std::string& message)
{
    return rootCertificateGeneratorLogPrefix + message;
}
} // namespace

RootCertificateGenerator::RootCertificateGenerator()
{
    check(
        gnutls_x509_crt_init(&certificate),
        createErrorMessage("Failed to initialize certificate."));

    check(
        gnutls_x509_crt_set_key_usage(
            certificate,
            GNUTLS_KEY_KEY_CERT_SIGN | GNUTLS_KEY_CRL_SIGN
                | GNUTLS_KEY_DIGITAL_SIGNATURE),
        createErrorMessage("Failed to set key usage."));

    check(
        gnutls_x509_crt_set_basic_constraints(certificate, 1, -1),
        createErrorMessage("Failed to set basic constraints."));

    check(
        gnutls_x509_crt_set_ca_status(certificate, 1),
        createErrorMessage("Failed to set CA status."));

    check(
        gnutls_x509_crt_set_key_purpose_oid(certificate, GNUTLS_KP_ANY, 0),
        createErrorMessage("Failed to set key purpose OID."));

    check(
        gnutls_x509_crt_set_subject_alternative_name(
            certificate, GNUTLS_SAN_DNSNAME, "localhost"),
        createErrorMessage("Failed to set subject alternative name."));
}

RootCertificateGenerator::~RootCertificateGenerator()
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

void RootCertificateGenerator::readPrivateKey(const std::string& privateKeyPath)
{
    gnutls_datum_t privateKeyData;
    check(
        gnutls_load_file(privateKeyPath.c_str(), &privateKeyData),
        createErrorMessage("Failed to load private key from file."));

    check(
        gnutls_x509_privkey_init(&privateKey),
        createErrorMessage("Failed to initialize private key."));

    check(
        gnutls_x509_privkey_import(
            privateKey, &privateKeyData, GNUTLS_X509_FMT_PEM),
        createErrorMessage("Failed to import private key."));

    check(
        gnutls_x509_crt_set_key(certificate, privateKey),
        createErrorMessage("Failed to set private key."));

    gnutls_free(privateKeyData.data);
}

void RootCertificateGenerator::setVersion(const int version)
{
    check(
        gnutls_x509_crt_set_version(certificate, version),
        createErrorMessage("Failed to set version."));
}

void RootCertificateGenerator::setSerialNumber(const std::string& serialNumber)
{
    check(
        gnutls_x509_crt_set_serial(
            certificate,
            static_cast<const void*>(serialNumber.data()),
            serialNumber.size()),
        createErrorMessage("Failed to set serial number."));
}

void RootCertificateGenerator::setActivationTime(
    std::chrono::system_clock::time_point activationTime)
{
    const auto activationTimeT =
        std::chrono::system_clock::to_time_t(activationTime);
    check(
        gnutls_x509_crt_set_activation_time(certificate, activationTimeT),
        createErrorMessage("Failed to set activation time."));
}

void RootCertificateGenerator::setExpirationTime(
    std::chrono::system_clock::time_point expirationTime)
{
    const auto expirationTimeT =
        std::chrono::system_clock::to_time_t(expirationTime);
    check(
        gnutls_x509_crt_set_expiration_time(certificate, expirationTimeT),
        createErrorMessage("Failed to set expiration time."));
}

void RootCertificateGenerator::setDistinguishedName(
    const std::string& distinguishedName)
{
    check(
        gnutls_x509_crt_set_dn(certificate, distinguishedName.c_str(), nullptr),
        createErrorMessage("Failed to set distinguished name."));
}

void RootCertificateGenerator::sign()
{
    check(
        gnutls_x509_crt_sign(certificate, certificate, privateKey),
        createErrorMessage("Failed to sign certificate."));
}

void RootCertificateGenerator::saveToFile(const std::string& certificatePath)
{
    gnutls_datum_t certificateData;
    check(
        gnutls_x509_crt_export2(
            certificate, GNUTLS_X509_FMT_PEM, &certificateData),
        createErrorMessage("Failed to export certificate."));

    FILE* certificateFile = fopen(certificatePath.c_str(), "w");
    if (! certificateFile)
    {
        throw std::runtime_error(
            createErrorMessage("Failed to open certificate file."));
    }

    if (fwrite(certificateData.data, 1, certificateData.size, certificateFile)
        != certificateData.size)
    {
        throw std::runtime_error(
            createErrorMessage("Failed to write certificate to file."));
    }

    fclose(certificateFile);
    gnutls_free(certificateData.data);
}
