#include "CertVerifier.hpp"
#include <iostream>
#include <cassert>
#include <cstdlib>

// ***** Test Helper Functions *****

// A simple assertion helper to provide better output.
void RunTest(const std::string& testName, bool result, bool expected)
{
   std::cout << "Running test: " << testName << "... ";
   if (result == expected)
   {
      std::cout << "PASSED" << std::endl;
   }
   else
   {
      std::cout << "FAILED" << std::endl;
      exit(EXIT_FAILURE);
   }
}

// ***** Test Cases *****

void TestGoodCertificate(const Cert::CertVerifier& verifier)
{
   // This test assumes 'certs/test_certs/good/valid_chain.pem' exists
   // and was signed by a root CA present in 'certs/trust_store'.
   // You must set this up for the test to pass.
   bool result = verifier.Verify("certs/test_certs/good/valid_chain.pem");
   RunTest("Good Certificate Chain", result, true);
}

void TestBadExpiredCertificate(const Cert::CertVerifier& verifier)
{
   // This test assumes 'certs/test_certs/bad_expired/expired_chain.pem' exists.
   // It should fail because the certificate is expired.
   bool result = verifier.Verify("certs/test_certs/bad_expired/expired_chain.pem");
   RunTest("Expired Certificate Chain", result, false);
}

void TestBadUntrustedCertificate(const Cert::CertVerifier& verifier)
{
   // This test assumes 'certs/test_certs/bad_untrusted/untrusted_chain.pem' exists.
   // It should fail because the root CA that signed it is not in our trust store.
   bool result = verifier.Verify("certs/test_certs/bad_untrusted/untrusted_chain.pem");
   RunTest("Untrusted Certificate Chain", result, false);
}

void TestNonExistentFile(const Cert::CertVerifier& verifier)
{
   bool result = verifier.Verify("non_existent_file.pem");
   RunTest("Non-Existent Certificate File", result, false);
}


int main()
{
   std::cout << "***** Starting Certificate Verifier Tests *****" << std::endl;

   try
   {
      // Initialize the verifier with the test trust store.
      // IMPORTANT: For these tests to work, you must populate the
      // 'certs/trust_store' directory with the correct root CA.
      Cert::CertVerifier verifier("certs/trust_store");

      // Run all tests
      TestGoodCertificate(verifier);
      TestBadExpiredCertificate(verifier);
      TestBadUntrustedCertificate(verifier);
      TestNonExistentFile(verifier);

      std::cout << "***** All Tests Passed *****" << std::endl;
      return EXIT_SUCCESS;
   }
   catch (const std::exception& e)
   {
      std::cerr << "Test setup failed: " << e.what() << std::endl;
      return EXIT_FAILURE;
   }
}