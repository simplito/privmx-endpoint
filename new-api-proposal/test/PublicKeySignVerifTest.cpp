#include <string>
#include <gtest/gtest.h>

// #include <privmx/crypto/ecc/PrivateKey.hpp>
// #include <privmx/utils/Utils.hpp>
#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"

#include "CryptoProviderRegistry.hpp"
#include "CryptoProviderFromDriver.hpp"

#include "PrivateKey.hpp"
#include "PublicKey.hpp"
#include "Utils.hpp"


using privmx::cryptoservice::CryptoProviderRegistry;
using privmx::cryptoservice::ICryptoProvider;
using privmx::cryptoservice::Bytes;
using privmx::cryptoservice::AsymAlg;
using privmx::cryptoservice::KeyFormat;
using privmx::cryptoservice::SigScheme;

using namespace std;

namespace privmx {
namespace cryptoservice {
namespace ecc {

TEST(PublicKeyTest, SignatureVerificationBasicTests) {
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

    Bytes sign1(priv1.sign(data, SigScheme::EcdsaSecp256k1Compact));
    Bytes sign1wh(priv1.sign(data, SigScheme::EcdsaSecp256k1CompactWithHash));
    Bytes sign2(priv2.sign(data, SigScheme::EcdsaSecp256k1Compact));
    Bytes sign2wh(priv2.sign(data, SigScheme::EcdsaSecp256k1CompactWithHash));

    string oldSign1(priv1.signToCompactSignature(messageToSign));
    EXPECT_TRUE(publ1.verifyCompactSignature(messageToSign, oldSign1));

    // string oldSign1wh(priv1.signToCompactSignatureWithHash(messageToSign));
    // EXPECT_TRUE(publ1.verifyCompactSignatureWithHash(messageToSign, oldSign1wh));

    // EXPECT_TRUE(publ1.verify(data, sign1,SigScheme::EcdsaSecp256k1Compact));
    // EXPECT_TRUE(publ1.verify(data, sign1wh,SigScheme::EcdsaSecp256k1CompactWithHash));
    
    // EXPECT_TRUE(publ2.verify(data, sign2,SigScheme::EcdsaSecp256k1Compact));
    // EXPECT_TRUE(publ2.verify(data, sign2wh,SigScheme::EcdsaSecp256k1CompactWithHash));
    
    // EXPECT_FALSE(publ1.verify(data, sign2,SigScheme::EcdsaSecp256k1Compact));
    // EXPECT_FALSE(publ1.verify(data, sign2wh,SigScheme::EcdsaSecp256k1CompactWithHash));
    
    // EXPECT_FALSE(publ2.verify(data, sign1,SigScheme::EcdsaSecp256k1Compact));
    // EXPECT_FALSE(publ2.verify(data, sign1wh,SigScheme::EcdsaSecp256k1CompactWithHash));
 
}

} // namespace ecc
} // namespace cryptoservice
} // namespace privmx
