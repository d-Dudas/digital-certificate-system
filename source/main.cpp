#include "Client.hpp"
#include "Constants.hpp"
#include "Server.hpp"
#include "logger/Logger.hpp"
#include "certificate/Issuer.hpp"
#include "certificate/Revocator.hpp"
#include "utils/Check.hpp"
#include "utils/File.hpp"

#include <iostream>

extern "C"
{
#include <gnutls/gnutls.h>
}

namespace
{
std::string resourcesPath{""};
auto getRootCertificatePath{[]()
                            {
                                return resourcesPath + "root.crt";
                            }};
auto getRootPrivateKeyPath{[]()
                           {
                               return resourcesPath + "private_key.pem";
                           }};

auto getDerivedCertificatePath{[]()
                               {
                                   return resourcesPath + "derived.crt";
                               }};

auto getDerivedPrivateKeyPath{[]()
                              {
                                  return resourcesPath + "derived_key.pem";
                              }};

void printUsage(const std::string& programName)
{
    std::cerr << "Usage: " << programName << " <path_to_resources_folder>"
              << std::endl;
}

OnErrorCallback onErrorCallback(const std::string& message)
{
    return [message](const std::string& error)
    {
        logger::Logger logger{"Main"};
        logger.print().error() << message << " (" << error << ")";
    };
}

void getResourcesPath(int argc, char* argv[])
{
    if (argc != 2)
    {
        printUsage(argv[0]);
        exit(1);
    }

    resourcesPath = std::string{argv[1]};
}

void generateRootCertificate()
{
    certificate::Issuer certificateIssuer{};
    certificateIssuer.setVersion(3);
    certificateIssuer.setSerialNumber("01");
    certificateIssuer.setActivationTime(std::chrono::system_clock::now());
    certificateIssuer.setExpirationTime(
        std::chrono::system_clock::now() + std::chrono::hours{24});
    certificateIssuer.setDistinguishedName(
        "CN=Root CA,O=Organization Name,C=Country");
    certificateIssuer.sign();

    certificateIssuer.exportPrivateKeyToFile(getRootPrivateKeyPath());
    certificateIssuer.exportCertificateToFile(getRootCertificatePath());
}

void generateDerivedCertificate(
    const int version = 3,
    const std::string& serialNumber = "02",
    const std::string& distinguishedName =
        "CN=Derived CA,O=Organization Name,C=Country",
    const std::chrono::system_clock::time_point activationTime =
        std::chrono::system_clock::now(),
    const std::chrono::system_clock::time_point expirationTime =
        std::chrono::system_clock::now() + std::chrono::hours{24},
    const std::string& certificatePath = getDerivedCertificatePath(),
    const std::string& privateKeyPath = getDerivedPrivateKeyPath())
{
    certificate::Issuer certificateIssuer{};
    certificateIssuer.setVersion(version);
    certificateIssuer.setSerialNumber(serialNumber);
    certificateIssuer.setActivationTime(activationTime);
    certificateIssuer.setExpirationTime(expirationTime);
    certificateIssuer.setDistinguishedName(distinguishedName);
    certificateIssuer.sign(getRootCertificatePath(), getRootPrivateKeyPath());

    certificateIssuer.exportCertificateToFile(certificatePath);
    certificateIssuer.exportPrivateKeyToFile(privateKeyPath);
}

void revokeCertificate()
{
    certificate::Revocator revocator{
        getRootCertificatePath(), getRootPrivateKeyPath()};
    revocator.revokeCertificate("02", std::chrono::system_clock::now());
    revocator.exportCRLToFile(resourcesPath + "crl.pem");

    revocator.isCertificateRevoked("02")
        ? std::cout << "Certificate revoked successfully" << std::endl
        : std::cerr << "Failed to revoke certificate" << std::endl;
}

void renewCertificateIfBelowThreshold(
    const std::string& certificatePath,
    const std::string& privateKeyPath)
{
    gnutls_x509_crt_t certificate;
    gnutls_x509_crt_init(&certificate);
    gnutls_datum_t certificateData{utils::readDatumFromFile(certificatePath)};

    utils::gnutlsCheck(
        gnutls_x509_crt_import(
            certificate, &certificateData, GNUTLS_X509_FMT_PEM),
        onErrorCallback("Failed to import certificate"));

    time_t validityThreshold = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() + std::chrono::hours{12});
    time_t expirationTime = gnutls_x509_crt_get_expiration_time(certificate);

    if (expirationTime > validityThreshold)
    {
        std::cout << "Certificate is below the validity threshold" << std::endl;
        return;
    }

    certificate::Issuer certificateIssuer{};
    certificateIssuer.setVersion(3);
    certificateIssuer.setSerialNumber("03");
    certificateIssuer.setActivationTime(std::chrono::system_clock::now());
    certificateIssuer.setExpirationTime(
        std::chrono::system_clock::now() + std::chrono::hours{24});
    certificateIssuer.setDistinguishedName(
        "CN=Derived CA,O=Organization Name,C=Country");
    certificateIssuer.sign(getRootCertificatePath(), getRootPrivateKeyPath());

    certificateIssuer.exportCertificateToFile(certificatePath);
    certificateIssuer.exportPrivateKeyToFile(privateKeyPath);

    std::cout << "Certificate renewed successfully: " << certificatePath
              << std::endl;
}
} // namespace

int main(int argc, char* argv[])
try
{
    logger::Logger logger{"Main"};
    logger.print().info() << "Starting application";
    getResourcesPath(argc, argv);

    gnutls_global_init();

    generateRootCertificate();
    generateDerivedCertificate();
    revokeCertificate();

    // Derived certificate has 24h validity, below the threshold, so this will fail
    renewCertificateIfBelowThreshold(
        getDerivedCertificatePath(), getDerivedPrivateKeyPath());

    generateDerivedCertificate(
        3,
        "03",
        "CN=Derived CA,O=Organization Name,C=Country",
        std::chrono::system_clock::now(),
        std::chrono::system_clock::now() + std::chrono::hours{10},
        getDerivedCertificatePath(),
        getDerivedPrivateKeyPath());

    // Derived certificate has 10h validity, so this will succeed
    renewCertificateIfBelowThreshold(
        getDerivedCertificatePath(), getDerivedPrivateKeyPath());

    Server server{getDerivedCertificatePath(), getDerivedPrivateKeyPath()};
    server.acceptOneClient();

    try
    {
        Client client{getDerivedCertificatePath(), getDerivedPrivateKeyPath()};
        client.connectToServer(hostname, port);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error during client connection: " << e.what()
                  << std::endl;
    }

    server.stop();

    gnutls_global_deinit();
    return 0;
}
catch (const std::exception& e)
{
    std::cerr << e.what() << std::endl;
    return 1;
}
catch (...)
{
    std::cerr << "Unknown exception" << std::endl;
    return 2;
}
