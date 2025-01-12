#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <thread>
#include <arpa/inet.h>
#include <unistd.h>
#include "Server.hpp"
#include "logger/Logger.hpp"

extern "C"
{
#include <gnutls/gnutls.h>
}

#include "certificate/Issuer.hpp"
#include "certificate/Revocator.hpp"
#include "utils/Check.hpp"
#include "utils/File.hpp"

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

    std::cout << "CRL exported successfully: " << resourcesPath + "crl.pem"
              << std::endl;
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

void performKeyExchange(const std::string& certificatePath)
{
    gnutls_x509_crt_t certificate;
    gnutls_certificate_credentials_t credentials;
    gnutls_session_t session;
    gnutls_priority_t priorityCache;

    try
    {
        // Initialize GNUTLS
        gnutls_x509_crt_init(&certificate);
        gnutls_certificate_allocate_credentials(&credentials);
        gnutls_init(&session, GNUTLS_CLIENT);

        // Load the certificate
        gnutls_datum_t certificateData =
            utils::readDatumFromFile(certificatePath);
        utils::gnutlsCheck(
            gnutls_x509_crt_import(
                certificate, &certificateData, GNUTLS_X509_FMT_PEM),
            onErrorCallback("Failed to import certificate"));

        gnutls_certificate_set_x509_key_file(
            credentials,
            certificatePath.c_str(),
            getDerivedPrivateKeyPath().c_str(),
            GNUTLS_X509_FMT_PEM);
        gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, credentials);

        // Set priorities
        utils::gnutlsCheck(
            gnutls_priority_init(&priorityCache, "NORMAL", nullptr),
            onErrorCallback("Failed to set priorities"));
        gnutls_priority_set(session, priorityCache);

        // Connect to server
        int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in serverAddr = {};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(8080); // Connect to port 5555
        serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

        if (connect(
                clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr))
            < 0)
        {
            throw std::runtime_error("Failed to connect to server");
        }

        gnutls_transport_set_int(session, clientSocket);

        // Perform handshake
        int ret = gnutls_handshake(session);
        if (ret < 0)
        {
            throw std::runtime_error(
                std::string{"TLS handshake failed: "} + gnutls_strerror(ret));
        }

        std::cout << "Key exchange performed successfully" << std::endl;

        // Derive a key from the master secret using PRF
        // constexpr size_t keyLength = 48; // Desired key length in bytes
        // unsigned char sessionKey[keyLength] = {0};
        // const char* label = "My Key Exchange"; // Custom label for the PRF
        // const char* context = "Key Exchange Context"; // Optional context

        char buffer[256] = {0};
        int bytesReceived = gnutls_record_recv(session, buffer, sizeof(buffer));
        if (bytesReceived < 0)
        {
            throw std::runtime_error(
                std::string{"Failed to receive data: "}
                + gnutls_strerror(bytesReceived));
        }

        std::cout << "Received from server: "
                  << std::string(buffer, bytesReceived) << std::endl;

        const char* cipher = gnutls_cipher_get_name(gnutls_cipher_get(session));
        const char* kx = gnutls_kx_get_name(gnutls_kx_get(session));
        const char* mac = gnutls_mac_get_name(gnutls_mac_get(session));
        std::cout << "Cipher: " << cipher << ", Key Exchange: " << kx
                  << ", MAC: " << mac << std::endl;

        // Close connection
        gnutls_bye(session, GNUTLS_SHUT_RDWR);
        close(clientSocket);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error during key exchange: " << e.what() << std::endl;
    }

    // Cleanup
    gnutls_deinit(session);
    gnutls_x509_crt_deinit(certificate);
    gnutls_certificate_free_credentials(credentials);
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

    std::this_thread::sleep_for(std::chrono::seconds{1});
    performKeyExchange(getDerivedCertificatePath());

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
