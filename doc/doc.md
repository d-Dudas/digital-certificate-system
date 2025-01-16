# Cryptographic concepts used

## Digital Certificate

A digital certificate is an electronic document that proves the validity of a public key. It includes the public key and other relevant informations, such as the issuer of the certificate, the subject, the validity period, etc.  

In this project several digital certificates will be created with different configurations and details.

### Structure

The structure of a digital certificate is as follows:  

- Version (specifies the format, e.g. X509 v3)
- Serial Number (an unique identifier assigned by the CA)
- Issuer (the entity that issued and signed the certificate, including the CA's details such as name and organization)
- Validity Period (defines the timeframe during which the certificate is valid)
  - Not Before (the starting date and time of the certificate's validity)
  - Not After (the expiration date and time of the certificate's validity)
- Subject (the entity to whom the certificate has been issued, including details like name, domain name, and organization)
- Subject Public Key Information (contains the subject's public key and specifies the public key algorithm used, e.g., RSA or ECDSA)
- Extensions (provides additional information or constraints, commonly including):
    - Key Usage (defines the purposes of the key, such as digital signature or key encipherment)
    - Extended Key Usage (specifies applications like server authentication or email encryption)
    - Subject Alternative Name (SAN) (lists additional domain names, IP addresses, or emails associated with the certificate)
    - Basic Constraints (indicates if the certificate can act as a CA and specifies the maximum path length)
- Signature Algorithm (specifies the algorithm used by the issuer to create the digital signature, e.g., SHA-256 with RSA)
- Signature (the digital signature created by the issuer using their private key to ensure authenticity and integrity)


### Root

A root certificate is a certificate that was signed by itself. It should identify in certificate authority (CA) and should be used to sign other derived certificates.  

In this project a single root certificate will be created with 24h validity that is used to sign other, derived certificates.

### Derived

A derived certificate is a certificate that was signed by another certificate.  

In this project several derived certificates are created in order to demonstrate certificate management through certificate revocation and renewel, and encrypted communication using digital certificate.

## Keys

In modern cryptography private/public or shared keys are used to encrypt/decrypt data.  

In this project for each certificate an associated key will be generated.

# Results

The generated certificates and keys can be found in the resources directory.

#### Authors

David Dudas, Adrian Dena
