/**********************************/
/*** ONLY FOR TEMPORARY TESTING ***/
/**********************************/

#include <string>
#include <iostream>
#include <iomanip>

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"

#include "CryptoProviderRegistry.hpp"
#include "CryptoProviderFromDriver.hpp"
#include "CryptoProviderFromOpenssl.hpp"

#include "ECC.hpp"
#include "PublicKey.hpp"
#include "PrivateKey.hpp"
#include "ExtKey.hpp"


using privmx::cryptoservice::CryptoProviderRegistry;
using privmx::cryptoservice::ICryptoProvider;
using privmx::cryptoservice::Bytes;
using privmx::cryptoservice::Hash;
using privmx::cryptoservice::AsymAlg;

using privmx::cryptoservice::ecc::PublicKey;
using privmx::cryptoservice::ecc::PrivateKey;

using privmx::cryptoservice::IPrivateKey;
using privmx::cryptoservice::IPublicKey;

using std::string;

void printString(string s) {
    std::cout << '\"' << std::setfill('0') << std::uppercase << std::hex;
    for(int i = 0; i < s.length(); i++) {
       std::cout << "\\x" << std::setw(2) << ((uint) s[i] & 0xff);
    }
    std::cout << '\"' << std::dec;
}


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

     b = CryptoProviderRegistry::get().randomBytes(1000);
     Bytes hash = CryptoProviderRegistry::get().digest(Hash::Sha256,b);
     std::cout << hash.size() << std::endl;

     b = CryptoProviderRegistry::get().randomBytes(1);
     hash = CryptoProviderRegistry::get().digest(Hash::Sha256,b);
     std::cout << hash.size() << std::endl;

     PrivateKey priv = PrivateKey::generateRandom();
     std::string serialized = priv.toWIF();
     std::cout << '"' << serialized << '"' << std::endl;

    std::shared_ptr<IPrivateKey> privKey = CryptoProviderRegistry::get().generatePrivateKey(AsymAlg::EccSecp256k1);
    std::shared_ptr<IPublicKey> publKey = privKey->publicKey();

// ---- vector for testing public keys ---
     const string wif1("L1YwTwAr8dQCBzfmXBzh6ggBkYbLuu15Tc7s4bajrRNDbsogs9a5");
     const string wif2("KwDzTrBejZw91hSpkoauVYnjgkm64DAb3UX1QBCRjf5BryiVK6jk");
     const string wif3("KwDiK7diMWJYFDV6pPbQ8BzgWznPa4evLqKwLncDpeMrEZA5E2Xp");
     const string wif4("KwDkPqYKx8R2zEPTP6QnPLsvYSwsqeCJKHsJ6GWncC3r4CaqViRB");

     const string expected_priv1("\x81\x3d\xe0\x0e\xb4\x3c\x22\x7e\xaf\x82\x47\x40\xbc\xee\x66\xf8\xb8\xe4\xc0\x83\x83\x34\x83\x65\x8c\x8c\x65\xe7\xd9\xcd\x76\xc9", 32);
     const string expected_priv2("\x00\x24\xf6\xbb\xb1\x0a\x74\xd9\x0a\xeb\xbc\xc3\xf4\xf1\x8a\x86\xda\xb8\x6c\x81\x51\x3b\x4a\x3b\x9d\x28\xe8\x26\xd6\xa7\x9a\x97", 32);
     const string expected_priv3("\x00\x00\x4a\xbc\x31\xdf\x4a\x0e\xc4\x9a\xec\x9e\xfa\x6d\xce\x2e\x6b\x3d\xa3\x99\x85\x6f\x13\xd0\xef\x56\x07\x6b\x62\x84\xab\x4d", 32);
     const string expected_priv4("\x00\x05\x04\x9f\x90\xde\x17\x9b\xb2\x6d\x66\x90\xdc\x68\x2d\xed\xb7\xcd\xa5\x03\x0b\x93\x7b\xd8\x7c\x65\x36\xdd\x46\x2a\x58\xf3", 32);

     PrivateKey priv1 = PrivateKey::fromWIF(wif1);
     PrivateKey priv2 = PrivateKey::fromWIF(wif2);
     PrivateKey priv3 = PrivateKey::fromWIF(wif3);
     PrivateKey priv4 = PrivateKey::fromWIF(wif4);

     PublicKey publ1 = priv1.getPublicKey();
     PublicKey publ2 = priv2.getPublicKey();
     PublicKey publ3 = priv3.getPublicKey();
     PublicKey publ4 = priv4.getPublicKey();

  
     std::cout << std::endl;

     string publ1Der = publ1.toDER();
     std::cout << "   const string expected_publ1Der(";
     printString(publ1Der);
     std::cout << ");" << std::endl;

     string publ2Der = publ2.toDER();
     std::cout << "   const string expected_publ2Der(";
     printString(publ2Der);
     std::cout << ");" << std::endl;

     string publ3Der = publ3.toDER();
     std::cout << "   const string expected_publ3Der(";
     printString(publ3Der);
     std::cout << ");" << std::endl;

     string publ4Der = publ4.toDER();
     std::cout << "   const string expected_publ4Der(";
     printString(publ4Der);
     std::cout << ");" << std::endl;

     std::cout << std::endl;

     string publ1Base58Der = publ1.toBase58DER();
     std::cout << "   const string expected_publ1Base58Der(\"" << publ1Base58Der << "\");" << std::endl;

     string publ2Base58Der = publ2.toBase58DER();
     std::cout << "   const string expected_publ2Base58Der(\"" << publ2Base58Der << "\");" << std::endl;

     string publ3Base58Der = publ3.toBase58DER();
     std::cout << "   const string expected_publ3Base58Der(\"" << publ3Base58Der << "\");" << std::endl;

     string publ4Base58Der = publ4.toBase58DER();
     std::cout << "   const string expected_publ4Base58Der(\"" << publ4Base58Der << "\");" << std::endl;

     std::cout << std::endl;


     string publ1Base58DerAddr = publ1.toBase58Address();
     std::cout << "   const string expected_publ1Base58DerAddr(\"" << publ1Base58DerAddr << "\");" << std::endl;

     string publ2Base58DerAddr = publ2.toBase58Address();
     std::cout << "   const string expected_publ2Base58DerAddr(\"" << publ2Base58DerAddr << "\");" << std::endl;

     string publ3Base58DerAddr = publ3.toBase58Address();
     std::cout << "   const string expected_publ3Base58DerAddr(\"" << publ3Base58DerAddr << "\");" << std::endl;

     string publ4Base58DerAddr = publ4.toBase58Address();
     std::cout << "   const string expected_publ4Base58DerAddr(\"" << publ4Base58DerAddr << "\");" << std::endl;

    return 0;
}



// }

//}