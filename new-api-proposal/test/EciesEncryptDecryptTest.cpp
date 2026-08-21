#include <string>
#include <gtest/gtest.h>

// #include <privmx/crypto/ecc/PrivateKey.hpp>
// #include <privmx/utils/Utils.hpp>
#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"

#include "CryptoProviderRegistry.hpp"
#include "CryptoProviderFromDriver.hpp"

#include "BN.hpp"
#include "Point.hpp"
#include "ECCImpl.hpp"

#include "PrivateKey.hpp"
#include "PublicKey.hpp"
#include "Utils.hpp"

#include "ECC.hpp"
#include "ECIES.hpp"


using privmx::cryptoservice::CryptoProviderRegistry;
using privmx::cryptoservice::ICryptoProvider;
using privmx::cryptoservice::Bytes;
using privmx::cryptoservice::AsymAlg;
using privmx::cryptoservice::KeyFormat;
using privmx::cryptoservice::SigScheme;

using privmx::cryptoservice::ecc::ECCImpl;

using namespace std;

namespace privmx {
namespace cryptoservice {
namespace ecc {

TEST(PrivateKeyTest, EncryptDecryptBasicTests) {

    const string messageToSign("Sample message");
    Bytes data(Utils::s2b(messageToSign));

    const string wif1("L1YwTwAr8dQCBzfmXBzh6ggBkYbLuu15Tc7s4bajrRNDbsogs9a5");
    const string wif2("KwDzTrBejZw91hSpkoauVYnjgkm64DAb3UX1QBCRjf5BryiVK6jk");
    const string wif3("KwDiK7diMWJYFDV6pPbQ8BzgWznPa4evLqKwLncDpeMrEZA5E2Xp");
    const string wif4("KwDkPqYKx8R2zEPTP6QnPLsvYSwsqeCJKHsJ6GWncC3r4CaqViRB");

    PrivateKey priv1 = PrivateKey::fromWIF(wif1);
    PrivateKey priv2 = PrivateKey::fromWIF(wif2);
    PrivateKey priv3 = PrivateKey::fromWIF(wif3);
    PrivateKey priv4 = PrivateKey::fromWIF(wif4);

    PublicKey publ1 = priv1.getPublicKey();
    PublicKey publ2 = priv2.getPublicKey();
    PublicKey publ3 = priv3.getPublicKey();
    PublicKey publ4 = priv4.getPublicKey();

    const string expected_ecies12_enc("\xC7\x09\x44\x6C\x13\x95\x0F\xDE\xDF\x20\x34\x02\xC9\xC9\x22\x8C\xF6\x4C\x9C\xB6\xA8\x3D\x31\xA5\x89\x87\x39\x28\xF1\x6A\x96\x3F\xBF\x8A\x2C\x1D");
    const string expected_ecies21_enc("\x3D\xE8\x21\xC2\x47\xF1\x36\xA7\x1B\x70\xF2\x9F\x89\xB7\xA9\xC6\x40\xA0\x08\xB4\x4E\x73\x13\x76\xE6\xD2\x23\x8D\xD7\x3D\x04\x86\xDB\xC1\x0D\x0A");
    const string expected_ecies34_enc("\x4C\xD5\x01\x33\xA5\x01\x1C\x61\xB2\x0A\xFD\x91\x6D\xE9\xB2\xCB\x9F\x41\x5A\xF7\xBF\x5D\x1F\x0A\x8A\x39\xB0\x44\x7D\x34\xB0\x89\x57\x5A\xB6\x56");
    const string expected_ecies43_enc("\xFD\x3C\xEE\xA0\x3A\x1E\x70\xA8\x54\x28\x51\x05\x9E\xD0\xBD\x34\x27\x09\x6D\xA2\xB8\xAB\xCF\xFD\x93\xAF\x57\xB4\xB8\x42\x8F\x84\x84\xEA\x2A\xCF");

    ECIES ecies12(priv1, publ2);
    ECIES ecies21(priv2, publ1);
    ECIES ecies34(priv3, publ4);
    ECIES ecies43(priv4, publ4);

    // encryption tests
    EXPECT_EQ(ecies12.encrypt(messageToSign), expected_ecies12_enc);
    EXPECT_EQ(ecies21.encrypt(messageToSign), expected_ecies21_enc);
    EXPECT_EQ(ecies34.encrypt(messageToSign), expected_ecies34_enc);
    EXPECT_EQ(ecies43.encrypt(messageToSign), expected_ecies43_enc);

    // decryption tests
    EXPECT_EQ(ecies12.decrypt(ecies12.encrypt(messageToSign)), messageToSign);
    EXPECT_EQ(ecies21.decrypt(ecies21.encrypt(messageToSign)), messageToSign);
    EXPECT_EQ(ecies34.decrypt(ecies34.encrypt(messageToSign)), messageToSign);
    EXPECT_EQ(ecies43.decrypt(ecies43.encrypt(messageToSign)), messageToSign);
}

} // namespace ecc
} // namespace cryptoservice
} // namespace privmx
