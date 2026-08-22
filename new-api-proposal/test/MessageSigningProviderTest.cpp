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

TEST(PrivateKeyTest, SigningVerifyingProviderTests) {

    const string messageToSign("Sample message");
    Bytes data(Utils::s2b(messageToSign));

    const string wif1("L1YwTwAr8dQCBzfmXBzh6ggBkYbLuu15Tc7s4bajrRNDbsogs9a5");
    const string wif2("KwDzTrBejZw91hSpkoauVYnjgkm64DAb3UX1QBCRjf5BryiVK6jk");
    const string wif3("KwDiK7diMWJYFDV6pPbQ8BzgWznPa4evLqKwLncDpeMrEZA5E2Xp");
    const string wif4("KwDkPqYKx8R2zEPTP6QnPLsvYSwsqeCJKHsJ6GWncC3r4CaqViRB");

    std::shared_ptr<ICryptoProvider> fromDriver
        = std::make_shared<privmx::cryptoservice::CryptoProviderFromDriver>();
    CryptoProviderRegistry::set(fromDriver);

    std::shared_ptr<IPrivateKey> priv1 = CryptoProviderRegistry::get().importPrivateKey(
        Utils::s2b(wif1), KeyFormat::Wif, AsymAlg::EccSecp256k1);
    std::shared_ptr<IPrivateKey> priv2 = CryptoProviderRegistry::get().importPrivateKey(
        Utils::s2b(wif2), KeyFormat::Wif, AsymAlg::EccSecp256k1);
    std::shared_ptr<IPrivateKey> priv3 = CryptoProviderRegistry::get().importPrivateKey(
        Utils::s2b(wif3), KeyFormat::Wif, AsymAlg::EccSecp256k1);
    std::shared_ptr<IPrivateKey> priv4 = CryptoProviderRegistry::get().importPrivateKey(
        Utils::s2b(wif4), KeyFormat::Wif, AsymAlg::EccSecp256k1);

    EXPECT_EQ(Utils::b2s(priv1->export_(KeyFormat::Wif)), wif1);
    EXPECT_EQ(Utils::b2s(priv2->export_(KeyFormat::Wif)), wif2);
    EXPECT_EQ(Utils::b2s(priv3->export_(KeyFormat::Wif)), wif3);
    EXPECT_EQ(Utils::b2s(priv4->export_(KeyFormat::Wif)), wif4);

    std::shared_ptr<IPublicKey> publ1 = priv1->publicKey();
    std::shared_ptr<IPublicKey> publ2 = priv2->publicKey();
    std::shared_ptr<IPublicKey> publ3 = priv3->publicKey();
    std::shared_ptr<IPublicKey> publ4 = priv4->publicKey();

    Bytes sign1(priv1->sign(data,SigScheme::EcdsaSecp256k1Compact));
    Bytes sign2(priv2->sign(data,SigScheme::EcdsaSecp256k1Compact));
    Bytes sign3(priv3->sign(data,SigScheme::EcdsaSecp256k1Compact));
    Bytes sign4(priv4->sign(data,SigScheme::EcdsaSecp256k1Compact));

    Bytes sign1wh(priv1->sign(data,SigScheme::EcdsaSecp256k1CompactWithHash));
    Bytes sign2wh(priv2->sign(data,SigScheme::EcdsaSecp256k1CompactWithHash));
    Bytes sign3wh(priv3->sign(data,SigScheme::EcdsaSecp256k1CompactWithHash));
    Bytes sign4wh(priv4->sign(data,SigScheme::EcdsaSecp256k1CompactWithHash));
     
    // EXPECT_TRUE(publ1->verify(data, Utils::s2b(((const PrivateKey&) (*priv1)).signToCompactSignature(messageToSign)), SigScheme::EcdsaSecp256k1Compact));
    // EXPECT_TRUE(publ2->verify(data, Utils::s2b(((const PrivateKey&) (*priv2)).signToCompactSignature(messageToSign)), SigScheme::EcdsaSecp256k1Compact));

    EXPECT_TRUE(publ1->verify(data, sign1, SigScheme::EcdsaSecp256k1Compact));
    EXPECT_TRUE(publ2->verify(data, sign2, SigScheme::EcdsaSecp256k1Compact));
    EXPECT_TRUE(publ3->verify(data, sign3, SigScheme::EcdsaSecp256k1Compact));
    EXPECT_TRUE(publ4->verify(data, sign4, SigScheme::EcdsaSecp256k1Compact));
    
    EXPECT_TRUE(publ1->verify(data, sign1wh, SigScheme::EcdsaSecp256k1CompactWithHash));
    EXPECT_TRUE(publ2->verify(data, sign2wh, SigScheme::EcdsaSecp256k1CompactWithHash));
    EXPECT_TRUE(publ3->verify(data, sign3wh, SigScheme::EcdsaSecp256k1CompactWithHash));
    EXPECT_TRUE(publ4->verify(data, sign4wh, SigScheme::EcdsaSecp256k1CompactWithHash));    

    EXPECT_FALSE(publ1->verify(data, sign2, SigScheme::EcdsaSecp256k1Compact));
    EXPECT_FALSE(publ2->verify(data, sign1, SigScheme::EcdsaSecp256k1Compact));
    EXPECT_FALSE(publ3->verify(data, sign4, SigScheme::EcdsaSecp256k1Compact));
    EXPECT_FALSE(publ4->verify(data, sign3, SigScheme::EcdsaSecp256k1Compact));
    
    EXPECT_FALSE(publ1->verify(data, sign2wh, SigScheme::EcdsaSecp256k1CompactWithHash));
    EXPECT_FALSE(publ2->verify(data, sign1wh, SigScheme::EcdsaSecp256k1CompactWithHash));
    EXPECT_FALSE(publ3->verify(data, sign4wh, SigScheme::EcdsaSecp256k1CompactWithHash));
    EXPECT_FALSE(publ4->verify(data, sign3wh, SigScheme::EcdsaSecp256k1CompactWithHash));    
}

} // namespace ecc
} // namespace cryptoservice
} // namespace privmx
