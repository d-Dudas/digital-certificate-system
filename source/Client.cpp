#include "Client.hpp"
#include "utils/Check.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace utils;

Client::Client(
    const std::string& certificatePath,
    const std::string& privateKeyPath)
{
    gnutls_certificate_allocate_credentials(&credentials);
    gnutls_init(&session, GNUTLS_CLIENT);

    gnutls_certificate_set_x509_key_file(
        credentials,
        certificatePath.c_str(),
        privateKeyPath.c_str(),
        GNUTLS_X509_FMT_PEM);
    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, credentials);

    gnutlsCheck(
        gnutls_priority_init(&priorityCache, "NORMAL", nullptr),
        onErrorCallback("Failed to initialize priority cache"));
    gnutls_priority_set(session, priorityCache);
}

Client::~Client()
{
    gnutls_deinit(session);
    gnutls_certificate_free_credentials(credentials);
    gnutls_priority_deinit(priorityCache);
}

OnErrorCallback Client::onErrorCallback(const std::string& message)
{
    return [this, message](const std::string& error)
    {
        logger.print().error() << message << " (" << error << ")";
    };
}

void Client::connectToServer(const std::string& hostname, int port)
{
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    check(clientSocket, onErrorCallback("Failed to create socket"));

    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = inet_addr(hostname.c_str());

    check(
        connect(
            clientSocket,
            (struct sockaddr*)&serverAddress,
            sizeof(serverAddress)),
        onErrorCallback("Failed to connect to server"));

    gnutls_transport_set_int(session, clientSocket);
    check(gnutls_handshake(session), onErrorCallback("TLS handshake failed"));

    logger.print().info() << "Handshake performed successfully";

    char buffer[256] = {0};
    int bytesReceived = gnutls_record_recv(session, buffer, sizeof(buffer));
    check(bytesReceived, onErrorCallback("Failed to receive data"));

    logger.print().info() << "Received from server: "
                          << std::string(buffer, bytesReceived);

    const std::string cipher{
        gnutls_cipher_get_name(gnutls_cipher_get(session))};
    const std::string kx{gnutls_kx_get_name(gnutls_kx_get(session))};
    const std::string mac{gnutls_mac_get_name(gnutls_mac_get(session))};

    logger.print().info() << "Cipher: " << cipher << ", Key Exchange: " << kx
                          << ", MAC: " << mac;

    // Close connection
    gnutls_bye(session, GNUTLS_SHUT_RDWR);
    close(clientSocket);
}
