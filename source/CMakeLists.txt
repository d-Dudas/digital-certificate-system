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

if(NOT DEFINED GNUTLS_INSTALL)
    message(FATAL_ERROR "The GNUTLS_INSTALL variable is not set (-DGNUTLS_INSTALL=...)")
endif()

if(DEFINED RESOURCES_PATH)
    add_definitions(-DRESOURCES_PATH=\"${RESOURCES_PATH}\")
endif()

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${GNUTLS_INSTALL}/lib/libgnutls.so)
include_directories(${GNUTLS_INSTALL}/include)

set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
