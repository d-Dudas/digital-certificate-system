#include "Server.hpp"
#include "Constants.hpp"
#include "logger/Logger.hpp"
#include "utils/Check.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace utils;

Server::Server(
    const std::string& certificatePath,
    const std::string& privateKeyPath)
{
    gnutls_certificate_allocate_credentials(&credentials);
    gnutls_certificate_set_x509_key_file(
        credentials,
        certificatePath.c_str(),
        privateKeyPath.c_str(),
        GNUTLS_X509_FMT_PEM);

    openSocket();

    gnutls_init(&session, GNUTLS_SERVER);
    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, credentials);
    gnutls_priority_set_direct(session, "NORMAL", nullptr);

    logger.print().info() << "Server created";
}

Server::~Server()
{
    stop();
    close(socket);
    gnutls_certificate_free_credentials(credentials);
    gnutls_deinit(session);

    logger.print().info() << "Server destroyed";
}

OnErrorCallback Server::onErrorCallback(const std::string& message) const
{
    return [this, message](const std::string& error)
    {
        logger.print().error() << message << " (" << error << ")";
    };
}

void Server::openSocket()
{
    socket = ::socket(AF_INET, SOCK_STREAM, 0);
    check(socket, onErrorCallback("Failed to create server socket"));

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    check(
        bind(socket, (sockaddr*)&serverAddress, sizeof(serverAddress)),
        onErrorCallback("Failed to bind server socket"));
    listen(socket, 5);
}

void Server::runThread()
{
    logger.print().info() << "Server started";

    int clientSocket = accept(socket, nullptr, nullptr);
    check(clientSocket, onErrorCallback("Failed to accept client connection"));

    gnutls_transport_set_int(session, clientSocket);

    gnutlsCheck(
        gnutls_handshake(session),
        onErrorCallback("Failed to perform handshake"));

    logger.print().info() << "New client connected. Handshake performed";

    const std::string welcomeMessage{"Hello, secure world!"};
    gnutls_record_send(
        session, welcomeMessage.c_str(), welcomeMessage.length());

    const std::string cipher{
        gnutls_cipher_get_name(gnutls_cipher_get(session))};
    const std::string kx{gnutls_kx_get_name(gnutls_kx_get(session))};
    const std::string mac{gnutls_mac_get_name(gnutls_mac_get(session))};

    logger.print().info() << "Cipher: " << cipher << ", Key Exchange: " << kx
                          << ", MAC: " << mac;

    close(clientSocket);

    gnutls_bye(session, GNUTLS_SHUT_RDWR);

    logger.print().info() << "Server stopped";
}

void Server::acceptOneClient()
{
    thread = std::thread{&Server::runThread, this};
}

void Server::stop()
{
    if (thread.joinable())
    {
        thread.join();
    }
}
