#include <gnutls/gnutls.h>
#include <iostream>

#include "CertificateIssuer.hpp"
#include "certificate/Revocator.hpp"

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
    CertificateIssuer certificateIssuer{};
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

    std::cout << "Root private key generated successfully: "
              << getRootPrivateKeyPath() << std::endl;
    std::cout << "Root certificate generated successfully: "
              << getRootCertificatePath() << std::endl;
}

void generateDerivedCertificate()
{
    CertificateIssuer certificateIssuer{};
    certificateIssuer.setVersion(3);
    certificateIssuer.setSerialNumber("02");
    certificateIssuer.setActivationTime(std::chrono::system_clock::now());
    certificateIssuer.setExpirationTime(
        std::chrono::system_clock::now() + std::chrono::hours{24});
    certificateIssuer.setDistinguishedName(
        "CN=Derived CA,O=Organization Name,C=Country");
    certificateIssuer.sign(getRootCertificatePath(), getRootPrivateKeyPath());

    certificateIssuer.exportCertificateToFile(getDerivedCertificatePath());
    certificateIssuer.exportPrivateKeyToFile(getDerivedPrivateKeyPath());

    std::cout << "Derived private key generated successfully: "
              << getDerivedPrivateKeyPath() << std::endl;
    std::cout << "Derived certificate generated successfully: "
              << getDerivedCertificatePath() << std::endl;
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

    std::cout << "CRL exported successfully: " << resourcesPath + "crl.pem"
              << std::endl;
}

} // namespace

int main(int argc, char* argv[])
try
{
    getResourcesPath(argc, argv);

    gnutls_global_init();

    generateRootCertificate();
    generateDerivedCertificate();
    revokeCertificate();

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
