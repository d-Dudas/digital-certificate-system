cmake_minimum_required(VERSION 3.0)
project(DigitalCertificateSystem)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -pedantic -Werror")

include_directories(include)
add_subdirectory(source)
