set(SOURCES
    main.cpp
    certificate/Issuer.cpp
    certificate/Revocator.cpp
    utils/Check.cpp
    utils/File.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} gnutls)

