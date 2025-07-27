cmake_minimum_required(VERSION 3.15)
project(X509Verifier VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# For MSYS2/MinGW users—point to your OpenSSL install
if (MINGW)
   set(OPENSSL_ROOT_DIR "C:/msys64/mingw64")
endif()

find_package(OpenSSL REQUIRED)

include_directories(
   ${PROJECT_SOURCE_DIR}/include
   ${OPENSSL_INCLUDE_DIR}
)

# Static library for verifier logic
add_library(cert_verifier STATIC
   src/CertVerifier.cpp
)
target_link_libraries(cert_verifier
   PRIVATE OpenSSL::SSL OpenSSL::Crypto
)

# Main application
add_executable(verifier_app src/main.cpp)
target_link_libraries(verifier_app PRIVATE cert_verifier)

# Tests
enable_testing()
add_executable(run_tests tests/TestVerifier.cpp)
target_link_libraries(run_tests PRIVATE cert_verifier)
add_test(NAME VerifierTests COMMAND run_tests)