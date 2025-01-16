## Description

This project aims to develop a digital certificate system capable of securing
communications over an unsecured channel with similar structure as the X.509
standard.

It shows some basic examples of working with certificates, from generation
to encrypted communication.

## Dependencies

- CMake
- GnuTLS
- Ninja (optional)

## How to build

`mkdir build && cd build`  
`cmake -GNinja ..`  
`ninja`  

## Howt to run after build

From build directory:  
`./source/DigitalCertificateSystem ../resources`
