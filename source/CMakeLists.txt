set(SOURCES
    main.cpp
    Check.cpp
    CertificateIssuer.cpp
    utils/File.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} gnutls)

