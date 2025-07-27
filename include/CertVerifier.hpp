#pragma once

#include "OpenSslWrappers.hpp"
#include <string>
#include <stdexcept>

namespace Cert
{
   /**
    * @class CertVerifier
    * @brief Loads a trust‐store (directory of PEM CAs) and verifies certificate chains against it.
    */
   class CertVerifier
   {
      
   public:
      /**
       * @param trustStoreDir path to directory containing PEM root-CA files.
       * @throws std::runtime_error if the store cannot be initialized.
       */
      explicit CertVerifier(const std::string& trustStoreDir);

      /**
       * @brief Verify the cert (and any chain) in PEM at pemPath.
       * @return true if valid and trusted, false otherwise.
       */
      bool Verify(const std::string& pemPath) const;

   private:
      // Holds the loaded root CAs
      X509_STORE_ptr m_pTrustStore;
      bool m_isInitialized{false};

   };

} // namespace Cert