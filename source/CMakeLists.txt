set(SOURCES
    main.cpp
    App.cpp
    Server.cpp
    Client.cpp
    certificate/Issuer.cpp
    certificate/Revocator.cpp
    utils/Check.cpp
    utils/File.cpp
    logger/Logger.cpp
    logger/Stream.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} gnutls)
