#include "CertVerifier.hpp"
#include <gtest/gtest.h>
#include <memory>
#include <filesystem>
#include <fstream>

class CertVerifierTest : public ::testing::Test {
protected:
   void SetUp() override {
      const std::string trustStorePath = "certs/trust_store";
      
      if (!std::filesystem::exists(trustStorePath)) {
         GTEST_SKIP() << "Trust store directory not found: " << trustStorePath
                      << ". Run 'python scripts/generate_test_certs.py' to create test certificates.";
      }

      try {
         verifier = std::make_unique<Cert::CertVerifier>(trustStorePath);
         ASSERT_NE(verifier, nullptr);
      } catch (const std::exception& e) {
         FAIL() << "Failed to initialize CertVerifier: " << e.what();
      }
   }

   void TearDown() override {
      verifier.reset();
   }

   void SkipIfCertificateNotFound(const std::string& certPath) const {
      if (!std::filesystem::exists(certPath)) {
         GTEST_SKIP() << "Test certificate not found: " << certPath
                      << ". Run 'python scripts/generate_test_certs.py' to create it.";
      }
   }

   std::unique_ptr<Cert::CertVerifier> verifier;
};




// ***** Test Cases *****


TEST_F(CertVerifierTest, ValidCertificateChain) {
   const std::string certPath = "certs/test_certs/good/valid_chain.pem";
   SkipIfCertificateNotFound(certPath);
   
   bool result = verifier->Verify(certPath);
   EXPECT_TRUE(result) << "Valid certificate chain should pass verification";
}

TEST_F(CertVerifierTest, ExpiredCertificate) {
   const std::string certPath = "certs/test_certs/bad_expired/expired_chain.pem";
   SkipIfCertificateNotFound(certPath);
   
   bool result = verifier->Verify(certPath);
   EXPECT_FALSE(result) << "Expired certificate should fail verification";
}

TEST_F(CertVerifierTest, UntrustedCertificate) {
   const std::string certPath = "certs/test_certs/bad_untrusted/untrusted_chain.pem";
   SkipIfCertificateNotFound(certPath);
   
   bool result = verifier->Verify(certPath);
   EXPECT_FALSE(result) << "Certificate from untrusted CA should fail verification";
}

TEST_F(CertVerifierTest, NonExistentCertificateFile) {
   const std::string nonExistentPath = "non_existent_file.pem";
   bool result = verifier->Verify(nonExistentPath);
   
   EXPECT_FALSE(result) << "Verification of non-existent file should return false";
}

TEST_F(CertVerifierTest, EmptyFilePath) {
   bool result = verifier->Verify("");
   EXPECT_FALSE(result) << "Verification with empty path should return false";
}

TEST_F(CertVerifierTest, InvalidFilePath) {
   const std::string invalidPath = "///invalid///path///*.pem";
   bool result = verifier->Verify(invalidPath);
   
   EXPECT_FALSE(result) << "Verification with invalid path should return false";
}

// ***** Trust Store Tests *****


class CertVerifierTrustStoreTest : public ::testing::Test {
protected:
   // No SetUp needed verifiers are created in individual tests
};

TEST_F(CertVerifierTrustStoreTest, InvalidTrustStorePath) {
   EXPECT_THROW({
      Cert::CertVerifier verifier("/non/existent/trust/store");
   }, std::runtime_error) << "Invalid trust store path should throw exception";
}

TEST_F(CertVerifierTrustStoreTest, EmptyTrustStorePath) {
   EXPECT_THROW({
      Cert::CertVerifier verifier("");
   }, std::runtime_error) << "Empty trust store path should throw exception";
}

TEST_F(CertVerifierTrustStoreTest, FileInsteadOfDirectory) {
   // Create a temporary file
   const std::string tempFile = "temp_test_file.txt";
   std::ofstream ofs(tempFile);
   ofs << "test";
   ofs.close();

   EXPECT_THROW({
      Cert::CertVerifier verifier(tempFile);
   }, std::runtime_error) << "File path instead of directory should throw exception";

   // Clean up
   std::filesystem::remove(tempFile);
}
