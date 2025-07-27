#include "CertVerifier.hpp"
#include <iostream>
#include <cstdlib> // For EXIT_SUCCESS, EXIT_FAILURE

int main(int argc, char* argv[])
{
   // Basic command-line argument validation
   if (argc != 3)
   {
      std::cerr << "Usage: " << argv[0] << " <trust_store_path> <cert_to_verify_path>" << std::endl;
      return EXIT_FAILURE;
   }

   std::string trustStorePath = argv[1];
   std::string certPath = argv[2];

   try
   {
      // Create the verifier instance. This will load the trust store.
      Cert::CertVerifier verifier(trustStorePath);

      // Perform the verification.
      if (verifier.Verify(certPath))
      {
         std::cout << "Verification Successful" << std::endl;
         return EXIT_SUCCESS;
      }
      else
      {
         // The Verify method already printed the specific error.
         return EXIT_FAILURE;
      }
   }
   catch (const std::exception& e)
   {
      std::cerr << "An exception occurred: " << e.what() << std::endl;
      return EXIT_FAILURE;
   }
}