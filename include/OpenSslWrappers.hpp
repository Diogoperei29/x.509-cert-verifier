#pragma once

#include <memory>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

namespace Cert
{
   // Free OpenSSLs I/O abstraction (BIOs) with BIO_free_all.
   struct BioDeleter
   {
      void operator()(BIO* b) const
      {
         BIO_free_all(b);
      }
   };

   // RAII wrappers ensure we never leak OpenSSL resources, even if exceptions are thrown.
   using BIO_ptr            = std::unique_ptr<BIO, BioDeleter>;
   using X509_ptr           = std::unique_ptr<X509, decltype(&X509_free)>;
   using X509_STORE_ptr     = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
   using X509_STORE_CTX_ptr = std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)>;

} // namespace Cert