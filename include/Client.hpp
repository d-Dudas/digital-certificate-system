#pragma once

#include <string>
#include "logger/Logger.hpp"

extern "C"
{
#include <gnutls/gnutls.h>
}

class Client
{
public:
    Client(
        const std::string& certificatePath,
        const std::string& privateKeyPath);
    ~Client();

    void connectToServer(const std::string& hostname, int port);

private:
    OnErrorCallback onErrorCallback(const std::string& message);

    logger::Logger logger{"Client"};
    gnutls_certificate_credentials_t credentials;
    gnutls_session_t session;
    gnutls_priority_t priorityCache;
};
