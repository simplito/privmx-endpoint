/**********************************/
/*** ONLY FOR TEMPORARY TESTING ***/
/**********************************/

#include <string>
#include <iostream>

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"

#include "CryptoProviderRegistry.hpp"
#include "CryptoProviderFromDriver.hpp"
#include "CryptoProviderFromOpenssl.hpp"

using privmx::cryptoservice::CryptoProviderRegistry;
using privmx::cryptoservice::ICryptoProvider;
using privmx::cryptoservice::Bytes;

int main (int argc, char const *argv[])
{
    std::shared_ptr<ICryptoProvider> fromDriver
         = std::make_shared<privmx::cryptoservice::CryptoProviderFromDriver>();
    std::shared_ptr<ICryptoProvider> fromOpenssl
         = std::make_shared<privmx::cryptoservice::CryptoProviderFromOpenssl>();

    CryptoProviderRegistry::set(fromDriver);
    std::cout << CryptoProviderRegistry::getptr() -> name() << std::endl;
    std::cout << CryptoProviderRegistry::get().name() << std::endl;

    CryptoProviderRegistry::set(fromOpenssl);
    std::cout << CryptoProviderRegistry::getptr() -> name() << std::endl;
    std::cout << CryptoProviderRegistry::get().name() << std::endl;

    Bytes b = CryptoProviderRegistry::get().randomBytes(3);
    std::cout << (int) b[0] << " " << (int) b[1] << " " << (int) b[2] << std::endl;

   CryptoProviderRegistry::set(fromDriver);
   b = CryptoProviderRegistry::get().randomBytes(3);
   std::cout << (int) b[0] << " " << (int) b[1] << " " << (int) b[2] << std::endl;

   return 0;
}
//}