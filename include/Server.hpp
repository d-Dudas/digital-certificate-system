#pragma once

#include <string>
#include <thread>
#include "logger/Logger.hpp"

extern "C"
{
#include <gnutls/gnutls.h>
}

class Server
{
public:
    Server(
        const std::string& certificatePath,
        const std::string& privateKeyPath);
    ~Server();

    void acceptOneClient();
    void stop();

private:
    OnErrorCallback onErrorCallback(const std::string& message) const;

    void openSocket();
    void runThread();

    logger::Logger logger{"Server"};
    gnutls_session_t session{};
    gnutls_certificate_credentials_t credentials{};
    int socket{};
    std::thread thread;
};
