#include "App.hpp"

#include <iostream>

namespace
{
void printUsage(const std::string& programName)
{
    std::cerr << "Usage: " << programName << " <path_to_resources_folder>"
              << std::endl;
}

std::string getResourcesPath(int argc, char* argv[])
{
    if (argc != 2)
    {
        printUsage(argv[0]);
        exit(1);
    }

    return std::string{argv[1]};
}
} // namespace

int main(int argc, char* argv[])
{
    App app{getResourcesPath(argc, argv)};
    app.showRootCertificateGeneration();
    app.showDerivedCertificateGeneration();
    app.showCertificateRevocation();
    app.showCertificateRenewal();
    app.showEncryptedCommunicationUsingCertificates();

    return 0;
}
