#include "CertVerifier.hpp"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>

namespace Cert
{
   CertVerifier::CertVerifier(const std::string& trustStoreDir) : m_pTrustStore(X509_STORE_new(), &X509_STORE_free)
   {
      if (!m_pTrustStore)
         throw std::runtime_error("Failed to create X509_STORE");

      namespace fs = std::filesystem;
      fs::path dir(trustStoreDir);

      if (!fs::exists(dir) || !fs::is_directory(dir))
         throw std::runtime_error("Trust store path is invalid: " + trustStoreDir);

      bool loadedAny = false;

      // Walk every file in the directory
      for (auto const& entry : fs::directory_iterator(dir))
      {
         if (!entry.is_regular_file())
            continue;

         auto ext = entry.path().extension().string();
         if (ext != ".pem" && ext != ".crt" && ext != ".cer")
            continue;

         // Open the file as a BIO
         BIO_ptr pBio(
            BIO_new_file(entry.path().string().c_str(), "r"),
            BioDeleter()
         );

         if (!pBio)
         {
            std::cerr << "Warning: cannot open CA file: " << entry.path() << "\n";
            continue;
         }

         // Read ALL certificates in that file
         while (true)
         {
            X509* raw = PEM_read_bio_X509(pBio.get(), nullptr, nullptr, nullptr);

            if (!raw) 
               break;

            if (X509_STORE_add_cert(m_pTrustStore.get(), raw) == 1)
               loadedAny = true;
            else
               std::cerr << "Warning: failed to add CA cert: " << entry.path() << "\n";

            X509_free(raw);
         }
      }

      if (!loadedAny)
         std::cerr << "Warning: no CA certificates loaded from " << trustStoreDir << "\n";

      ERR_clear_error();
      m_isInitialized = true;
   }

   bool CertVerifier::Verify(const std::string& pemPath) const
   {
      if (!m_isInitialized)
      {
         std::cerr << "Error: verifier not initialized\n";
         return false;
      }

      // Load the chain from PEM
      BIO_ptr pBio(
         BIO_new_file(pemPath.c_str(), "r"),
         BioDeleter()
      );

      if (!pBio)
      {
         std::cerr << "Cannot open PEM: " << pemPath << "\n";
         return false;
      }

      X509_ptr pCert(
         PEM_read_bio_X509(pBio.get(), nullptr, nullptr, nullptr),
         &X509_free
      );

      if (!pCert)
      {
         std::cerr << "Failed to parse PEM: " << pemPath << "\n";
         return false;
      }

      // Create and init the verify‐context
      X509_STORE_CTX_ptr pCtx(
         X509_STORE_CTX_new(),
         &X509_STORE_CTX_free
      );

      if (!pCtx)
      {
         std::cerr << "Failed to create X509_STORE_CTX\n";
         return false;
      }

      if (X509_STORE_CTX_init(
            pCtx.get(),
            m_pTrustStore.get(),
            pCert.get(),
            nullptr
          ) != 1)
      {
         std::cerr << "X509_STORE_CTX_init failed\n";
         return false;
      }

      int ok = X509_verify_cert(pCtx.get());
      if (ok == 1)
      {
         return true;
      }
      else if (ok == 0)
      {
         int err = X509_STORE_CTX_get_error(pCtx.get());
         const char* msg = X509_verify_cert_error_string(err);
         std::cerr << "Verification Failed: " << msg << " (" << err << ")\n";
         return false;
      }
      else
      {
         unsigned long e = ERR_get_error();
         char buf[256];
         ERR_error_string_n(e, buf, sizeof(buf));
         std::cerr << "Internal Error: " << buf << "\n";
         return false;
      }
   }

} // namespace Cert