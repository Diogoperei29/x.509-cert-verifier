cmake_minimum_required(VERSION 3.16)
project(X509Verifier VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# Fetch nlohmann/json
FetchContent_Declare(
   json 
   URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
)
FetchContent_MakeAvailable(json)

# Fetch Google Test
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.17.0
)
FetchContent_MakeAvailable(googletest)

# Find OpenSSL (system installation required)
find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    message(STATUS "Found OpenSSL ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
endif()

# Compiler warnings after external libraries
set(WARNING_FLAGS
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
)

include_directories(
   ${PROJECT_SOURCE_DIR}/include
   ${OPENSSL_INCLUDE_DIR}
)

add_library(cert_verifier STATIC
   src/CertVerifier.cpp
   src/CertVerifierConfig.cpp
)
target_link_libraries(cert_verifier
   PRIVATE OpenSSL::SSL OpenSSL::Crypto
   PRIVATE nlohmann_json::nlohmann_json
)

add_executable(verifier_app src/main.cpp)
target_link_libraries(verifier_app PRIVATE cert_verifier)


enable_testing()
add_executable( run_tests
   tests/TestVerifier.cpp
)
target_link_libraries(run_tests PRIVATE cert_verifier gtest gtest_main)
target_compile_options(run_tests PRIVATE ${WARNING_FLAGS})

# Add tests to CTest
# Set working directory to project root so tests can find the certs directory
add_test(NAME VerifierTests COMMAND run_tests WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})