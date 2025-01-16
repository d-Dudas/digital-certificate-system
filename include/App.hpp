#pragma once

#include <string>
#include <chrono>

#include "logger/Logger.hpp"

class App
{
public:
    App(const std::string& resourcesPath);
    ~App();

    void showRootCertificateGeneration() const;
    void showDerivedCertificateGeneration() const;
    void showCertificateRevocation() const;
    void showCertificateRenewal() const;
    void showEncryptedCommunicationUsingCertificates() const;

private:
    std::string getRootCertificatePath() const;
    std::string getRootPrivateKeyPath() const;
    std::string getDerivedCertificatePath() const;
    std::string getDerivedPrivateKeyPath() const;

    void generateRootCertificate() const;
    void generateDerivedCertificate(
        const int& version,
        const std::string& serialNumber,
        const std::string& distinguishedName,
        const std::chrono::system_clock::time_point& activationTime,
        const std::chrono::system_clock::time_point& expirationTime,
        const std::string& certificatePath,
        const std::string& privateKeyPath) const;
    void revokeCertificate(const std::string& serialNumber) const;
    void renewCertificateIfBelowThreshold(
        const std::string& certificatePath) const;

    OnErrorCallback onErrorCallback(const std::string& message) const;

    const logger::Logger logger{"App"};
    const std::string resourcesPath;
};
