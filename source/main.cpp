#include "App.hpp"

#include <iostream>

namespace
{
#ifndef RESOURCES_PATH
void printUsage(const std::string& programName)
{
    std::cerr << "Usage: " << programName << " <path_to_resources_folder>"
              << std::endl;
}
#endif

std::string getResourcesPath(
    [[__maybe_unused__]] int argc,
    [[__maybe_unused__]] char* argv[])
{
#ifdef RESOURCES_PATH
    return std::string{RESOURCES_PATH};
#else
    if (argc != 2)
    {
        printUsage(argv[0]);
        exit(1);
    }

    return std::string{argv[1]};
#endif
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
