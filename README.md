# X.509 Certificate Chain Verifier

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![C++ Standard](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/std/the-standard) [![Build System](https://img.shields.io/badge/Build-CMake-orange.svg)](https://cmake.org/) [![Requires Python](https://img.shields.io/badge/requires-Python%203.7%2B%20%7C%20cryptography-blue.svg)](https://www.python.org/)  

A robust, secure, and modern C++ utility for loading and verifying X.509 certificate chains against a local trust store using the OpenSSL library.

## Summary

This project provides a `CertVerifier` class that encapsulates the logic for X.509 certificate verification. It is built with a strong emphasis on security and resource safety, using modern C++ RAII patterns to manage OpenSSL's C-style resources.

The work flow of this class is as such:
 - Loads all PEM-encoded root CAs from a directory  
 - Verifies a certificate or full chain against that trust store  
 - Uses RAII wrappers (`std::unique_ptr`) to manage OpenSSL resources  
A small `verifier_app` executable demonstrates usage, and a test suite verifies valid, expired, and untrusted chains.

## Features

-   **Secure by Default**: Fails closed and provides clear error messages on verification failure.
-   **RAII Wrappers**: Utilizes `std::unique_ptr` with custom deleters for all OpenSSL objects (`X509`, `X509_STORE_CTX`, etc.) to prevent resource leaks.
-   **Dynamic Trust Store**: Manual, filesystem-based trust-store loading
-   **CMake Build System**: Plain C++ build with CMake 
-   **Test Suite**: Includes tests for valid, expired, and untrusted certificate chains.
-   **Certificate creation**: Python script to generate test certificates automatically

## Prerequisites

To build and run this project, you will need:
 - C++17-capable compiler (GCC 7+, Clang 6+, or MSVC)  
 - CMake 3.15 or newer  
 - OpenSSL development libraries  
 - Python 3.7+ and the `cryptography` library (`pip install cryptography`)

## Installing on MSYS2/MinGW

1. Open the “MSYS2 MinGW 64-bit” shell and run:  
```bash
pacman -Syu  
pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl mingw-w64-x86_64-toolchain  
```

2. Verify:  
```bash
cmake --version  
openssl version
```

## How to Build

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Diogoperei29/X.509-Certificate-Chain-Verifier.git x509-verifier
    cd x509-verifier
    ```

2.  **Configure with CMake:**
    ```bash
    cmake -S . -B build -DOPENSSL_ROOT_DIR="C:/msys64/mingw64"
    ```

3.  **Compile the project:**
    ```bash
    cmake --build build
    ```
    The executables `verifier_app` and `run_tests` will be created in the `build/` directory.


## Generating Test Certificates
A Python script automates creation of test certs:  
`scripts/generate_test_certs.py`


1. Install `cryptography`:  
```bash
pip install cryptography  
```

2. Run:  
```bash
python3 scripts/generate_test_certs.py  
```
<br />

This produces:  
 - `certs/trust_store/rootCA.key` & `rootCA.pem`   
 - `certs/test_certs/good/valid_chain.pem`  
 - `certs/test_certs/bad_expired/expired_chain.pem`  
 - `certs/test_certs/bad_untrusted/untrustedCA.pem` & `untrusted_chain.pem`


## How to Use

### 1. Prepare the Trust Store

The verifier needs a "trust store" — a directory containing the root Certificate Authority (CA) certificates that you trust. These certificates must be in PEM format (`.pem`, `.crt`).

1.  Create a directory to act as your trust store. For this project, we use `certs/trust_store/`.
2.  Add your trusted root CA PEM files to this directory. You can often acquire these from browser vendors or your operating system's trust store.

    For example, to add a root CA:
    ```bash
    cp /path/to/your/root-ca.pem certs/trust_store/
    ```

### 2. Run the Verifier

The main application `verifier_app` takes two arguments:
1.  The path to the trust store directory.
2.  The path to the certificate (or certificate chain) file to verify.

**Example:**
```bash
# This command assumes you have a valid root CA in the trust_store
# that signed the certificate chain in valid_chain.pem.
./build/verifier_app certs/trust_store certs/test_certs/good/valid_chain.pem
```

**Expected Output (Success):**
```bash
Verification Successful
```
**Expected Output (Failure):**
```bash
Verification Failed: [reason] 
```

## Running Tests

The project includes a simple test runner to verify its core logic against known good and bad certificates.

To run the tests, first ensure you have built the project, then execute:
```bash
./build/run_tests
```

**Expected output:**
```
***** Starting Certificate Verifier Tests *****
Running test: Good Certificate Chain... PASSED
Verification Failed: certificate has expired (10)
Running test: Expired Certificate Chain... PASSED
Verification Failed: unable to get local issuer certificate (20)
Running test: Untrusted Certificate Chain... PASSED
Cannot open PEM: non_existent_file.pem
Running test: Non-Existent Certificate File... PASSED
***** All Tests Passed *****
```

## Security Considerations

 - **Trust-store integrity**: protect certs/trust_store/ with strict permissions  
 - **No revocation checking**: consider CRL or OCSP for production  
 - Keep OpenSSL and the Python `cryptography` library up-to-date  
 - Only files ending in .pem, .crt, .cer are loaded as CAs