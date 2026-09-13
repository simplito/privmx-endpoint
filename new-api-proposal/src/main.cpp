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

#include "PrivateKey2.hpp"
#include "AsyncKeyUtils.hpp"

#include "Utils.hpp"


using privmx::cryptoservice::CryptoProviderRegistry;
using privmx::cryptoservice::ICryptoProvider;
using privmx::cryptoservice::Bytes;
using privmx::cryptoservice::Hash;
using privmx::cryptoservice::AsymAlg;

using privmx::cryptoservice::ecc::PublicKey;
using privmx::cryptoservice::ecc::PrivateKey;

using privmx::cryptoservice::IPrivateKey;
using privmx::cryptoservice::IPublicKey;

// using privmx::cryptoservice::ecc::AsyncKeyUtils;
using privmx::cryptoservice::AsyncKeyUtils;

using privmx::cryptoservice::ecc::PrivateKey2;

using privmx::cryptoservice::ecc::Utils;


using std::string;

/*
 * Fixed data to represent the private and public key (P-256).
 */
const unsigned char priv_data[] = {
    0xb9, 0x2f, 0x3c, 0xe6, 0x2f, 0xfb, 0x45, 0x68,
    0x39, 0x96, 0xf0, 0x2a, 0xaf, 0x6c, 0xda, 0xf2,
    0x89, 0x8a, 0x27, 0xbf, 0x39, 0x9b, 0x7e, 0x54,
    0x21, 0xc2, 0xa1, 0xe5, 0x36, 0x12, 0x48, 0x5d
};
/* UNCOMPRESSED FORMAT */
const unsigned char pub_data[] = {
    POINT_CONVERSION_UNCOMPRESSED,
    0xcf, 0x20, 0xfb, 0x9a, 0x1d, 0x11, 0x6c, 0x5e,
    0x9f, 0xec, 0x38, 0x87, 0x6c, 0x1d, 0x2f, 0x58,
    0x47, 0xab, 0xa3, 0x9b, 0x79, 0x23, 0xe6, 0xeb,
    0x94, 0x6f, 0x97, 0xdb, 0xa3, 0x7d, 0xbd, 0xe5,
    0x26, 0xca, 0x07, 0x17, 0x8d, 0x26, 0x75, 0xff,
    0xcb, 0x8e, 0xb6, 0x84, 0xd0, 0x24, 0x02, 0x25,
    0x8f, 0xb9, 0x33, 0x6e, 0xcf, 0x12, 0x16, 0x2f,
    0x5c, 0xcd, 0x86, 0x71, 0xa8, 0xbf, 0x1a, 0x47
};


void printString(string s) {
    std::cout << '\"' << std::setfill('0') << std::uppercase << std::hex;
    for(int i = 0; i < s.length(); i++) {
       std::cout << "\\x" << std::setw(2) << ((uint) s[i] & 0xff);
    }
    std::cout << '\"' << std::dec;
}


int main (int argc, char const *argv[])
{

    return 0;
}

// }

//}