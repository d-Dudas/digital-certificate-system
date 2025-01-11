#include <gnutls/gnutls.h>
#include <iostream>

#include <RootCertificateGenerator.hpp>

namespace
{
const std::string resourcesPath{"resources/"};
const std::string rootCertificatePath{resourcesPath + "root.crt"};
const std::string rootPrivateKeyPath{resourcesPath + "private_key.pem"};
} // namespace

int main()
try
{
    gnutls_global_init();

    RootCertificateGenerator rootCertificateGenerator{};
    rootCertificateGenerator.readPrivateKey(rootPrivateKeyPath);
    rootCertificateGenerator.setVersion(3);
    rootCertificateGenerator.setSerialNumber("01");
    rootCertificateGenerator.setActivationTime(
        std::chrono::system_clock::now());
    rootCertificateGenerator.setExpirationTime(
        std::chrono::system_clock::now() + std::chrono::hours{24});
    rootCertificateGenerator.setDistinguishedName("CN=Root CA,O=Organization Name,C=Country");
    rootCertificateGenerator.sign();

    rootCertificateGenerator.saveToFile(rootCertificatePath);

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
