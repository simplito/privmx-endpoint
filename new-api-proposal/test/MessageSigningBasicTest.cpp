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

TEST(PrivateKeyTest, SigningVerifyingBasicTests) {

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

    string sign1(priv1.signToCompactSignature(messageToSign));
    string sign2(priv2.signToCompactSignature(messageToSign));
    string sign3(priv3.signToCompactSignature(messageToSign));
    string sign4(priv4.signToCompactSignature(messageToSign));

    string sign1wh(priv1.signToCompactSignatureWithHash(messageToSign));
    string sign2wh(priv2.signToCompactSignatureWithHash(messageToSign));
    string sign3wh(priv3.signToCompactSignatureWithHash(messageToSign));
    string sign4wh(priv4.signToCompactSignatureWithHash(messageToSign));

    EXPECT_TRUE(publ1.verifyCompactSignature(messageToSign, sign1));
    EXPECT_TRUE(publ2.verifyCompactSignature(messageToSign, sign2));
    EXPECT_TRUE(publ3.verifyCompactSignature(messageToSign, sign3));
    EXPECT_TRUE(publ4.verifyCompactSignature(messageToSign, sign4));

    EXPECT_TRUE(publ1.verifyCompactSignatureWithHash(messageToSign, sign1wh));
    EXPECT_TRUE(publ2.verifyCompactSignatureWithHash(messageToSign, sign2wh));
    EXPECT_TRUE(publ3.verifyCompactSignatureWithHash(messageToSign, sign3wh));
    EXPECT_TRUE(publ4.verifyCompactSignatureWithHash(messageToSign, sign4wh));

    EXPECT_FALSE(publ1.verifyCompactSignature(messageToSign, sign2));
    EXPECT_FALSE(publ2.verifyCompactSignature(messageToSign, sign1));
    EXPECT_FALSE(publ3.verifyCompactSignature(messageToSign, sign4));
    EXPECT_FALSE(publ4.verifyCompactSignature(messageToSign, sign3));

    EXPECT_FALSE(publ1.verifyCompactSignatureWithHash(messageToSign, sign2wh));
    EXPECT_FALSE(publ2.verifyCompactSignatureWithHash(messageToSign, sign1wh));
    EXPECT_FALSE(publ3.verifyCompactSignatureWithHash(messageToSign, sign4wh));
    EXPECT_FALSE(publ4.verifyCompactSignatureWithHash(messageToSign, sign3wh));
}

} // namespace ecc
} // namespace cryptoservice
} // namespace privmx
