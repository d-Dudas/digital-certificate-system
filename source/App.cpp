#include "App.hpp"
#include "certificate/Issuer.hpp"
#include "certificate/Revocator.hpp"
#include "Client.hpp"
#include "Constants.hpp"
#include "Server.hpp"
#include "utils/File.hpp"

namespace
{
constexpr std::string_view rootCertificateFile{"root.crt"};
constexpr std::string_view rootPrivateKeyFile{"private_key.pem"};
constexpr std::string_view derivedCertificateFile{"derived.crt"};
constexpr std::string_view derivedPrivateKeyFile{"derived_key.pem"};

bool isCertificateBelowValidityThreshold(gnutls_x509_crt_t& certificate)
{
    time_t validityThreshold{std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() + std::chrono::hours{12})};
    time_t expirationTime{gnutls_x509_crt_get_expiration_time(certificate)};

    return expirationTime > validityThreshold;
}
} // namespace

App::App(const std::string& resourcesPath)
: resourcesPath{resourcesPath}
{
    gnutls_global_init();
}

App::~App()
{
    gnutls_global_deinit();
}

void App::showRootCertificateGeneration() const
try
{
    logger.print().withoutPrefix()
        << "\n*** Generating root certificate... ***";
    generateRootCertificate();
    logger.print().withoutPrefix()
        << "*** Root certificate generated successfully. ***\n";
}
catch (const std::exception& e)
{
    logger.print().error() << e.what();
}
catch (...)
{
    logger.print().error() << "Unknown exception";
}

void App::showDerivedCertificateGeneration() const
try
{
    logger.print().withoutPrefix()
        << "\n*** Generating derived certificate... ***";
    generateDerivedCertificate(
        3,
        "02",
        "CN=Derived CA,O=Organization Name,C=Country",
        std::chrono::system_clock::now(),
        std::chrono::system_clock::now() + std::chrono::hours{24},
        getDerivedCertificatePath(),
        getDerivedPrivateKeyPath());
    logger.print().withoutPrefix()
        << "*** Derived certificate generated successfully. ***\n";
}
catch (const std::exception& e)
{
    logger.print().error() << e.what();
}
catch (...)
{
    logger.print().error() << "Unknown exception";
}

void App::showCertificateRevocation() const
try
{
    logger.print().withoutPrefix() << "\n*** Revoking certificate... ***";
    revokeCertificate("02");
    logger.print().withoutPrefix()
        << "*** Certificate revoked successfully. ***\n";
}
catch (const std::exception& e)
{
    logger.print().error() << e.what();
}
catch (...)
{
    logger.print().error() << "Unknown exception";
}

void App::showCertificateRenewal() const
try
{
    logger.print().withoutPrefix()
        << "\n*** Renewing certificate if below threshold... ***";
    logger.print().info() << "Derived certificate has 24h validity, below the "
                             "threshold, so this will fail";
    renewCertificateIfBelowThreshold(getDerivedCertificatePath());

    logger.print().info() << "Renewing certificate with 10h validity...";

    generateDerivedCertificate(
        3,
        "03",
        "CN=Derived CA,O=Organization Name,C=Country",
        std::chrono::system_clock::now(),
        std::chrono::system_clock::now() + std::chrono::hours{10},
        getDerivedCertificatePath(),
        getDerivedPrivateKeyPath());

    renewCertificateIfBelowThreshold(getDerivedCertificatePath());

    logger.print().withoutPrefix()
        << "*** Certificate renewed successfully. ***\n";
}
catch (const std::exception& e)
{
    logger.print().error() << e.what();
}
catch (...)
{
    logger.print().error() << "Unknown exception";
}

void App::showEncryptedCommunicationUsingCertificates() const
try
{
    logger.print().withoutPrefix()
        << "\n*** Starting encrypted communication using certificates... ***";

    {
        Server server{getDerivedCertificatePath(), getDerivedPrivateKeyPath()};
        server.acceptOneClient();

        try
        {
            Client client{
                getDerivedCertificatePath(), getDerivedPrivateKeyPath()};
            client.connectToServer(hostname.data(), port);
        }
        catch (const std::exception& e)
        {
            logger.print().error()
                << "Error during client connection: " << e.what();
        }

        server.stop();
    }

    logger.print().withoutPrefix()
        << "*** Encrypted communication using certificates finished. ***\n";
}
catch (const std::exception& e)
{
    logger.print().error() << e.what();
}
catch (...)
{
    logger.print().error() << "Unknown exception";
}

OnErrorCallback App::onErrorCallback(const std::string& message) const
{
    return [this, message](const std::string& error)
    {
        logger.print().error() << message << " (" << error << ")";
    };
}

std::string App::getRootCertificatePath() const
{
    return resourcesPath + rootCertificateFile.data();
}

std::string App::getRootPrivateKeyPath() const
{
    return resourcesPath + rootPrivateKeyFile.data();
}

std::string App::getDerivedCertificatePath() const
{
    return resourcesPath + derivedCertificateFile.data();
}

std::string App::getDerivedPrivateKeyPath() const
{
    return resourcesPath + derivedPrivateKeyFile.data();
}

void App::generateRootCertificate() const
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

void App::generateDerivedCertificate(
    const int& version,
    const std::string& serialNumber,
    const std::string& distinguishedName,
    const std::chrono::system_clock::time_point& activationTime,
    const std::chrono::system_clock::time_point& expirationTime,
    const std::string& certificatePath,
    const std::string& privateKeyPath) const
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

void App::revokeCertificate(const std::string& serialNumber) const
{
    certificate::Revocator revocator{
        getRootCertificatePath(), getRootPrivateKeyPath()};
    revocator.revokeCertificate(serialNumber, std::chrono::system_clock::now());
    revocator.exportCRLToFile(resourcesPath + "crl.pem");

    revocator.isCertificateRevoked(serialNumber)
        ? logger.print().info() << "Certificate with serial number "
                                << serialNumber << " has been revoked."
        : logger.print().warning()
              << "Failed to revoke certificate with serial number "
              << serialNumber;
}

void App::renewCertificateIfBelowThreshold(
    const std::string& certificatePath) const
{
    gnutls_x509_crt_t certificate{
        utils::importCertificateFromFile(certificatePath)};

    if (isCertificateBelowValidityThreshold(certificate))
    {
        logger.print().warning()
            << "Certificate is below the validity threshold";
        return;
    }

    generateDerivedCertificate(
        3,
        "03",
        "CN=Derived CA,O=Organization Name,C=Country",
        std::chrono::system_clock::now(),
        std::chrono::system_clock::now() + std::chrono::hours{24},
        getRootCertificatePath(),
        getRootPrivateKeyPath());

    logger.print().info() << "Certificate renewed successfully: "
                          << certificatePath;
}
