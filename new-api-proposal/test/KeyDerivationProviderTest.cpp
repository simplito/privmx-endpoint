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

TEST(PrivateKeyTest, KeyDerivationProviderTests) {
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

    const string expected_derPriv1Pub2("\x11\x5F\x05\xC6\x0D\x54\xDB\x1D\xAD\x83\x07\x55\x12\x72\x3F\x34\xF9\x3B\x82\x40\xC3\x30\x58\x97\xD3\xFD\xDD\x85\xFA\x24\x5E\x34");
    const string expected_derPriv2Pub1("\x11\x5F\x05\xC6\x0D\x54\xDB\x1D\xAD\x83\x07\x55\x12\x72\x3F\x34\xF9\x3B\x82\x40\xC3\x30\x58\x97\xD3\xFD\xDD\x85\xFA\x24\x5E\x34");
    const string expected_derPriv3Pub4("\x0F\x47\xBD\xE4\x90\x06\xCC\x40\x67\x53\x32\x88\xF0\x42\x18\x42\x71\x2E\x0C\xB9\x53\xBA\xB9\x6B\x82\xCD\xF5\xE0\x93\x8D\xBC\xD1");
    const string expected_derPriv4Pub3("\x0F\x47\xBD\xE4\x90\x06\xCC\x40\x67\x53\x32\x88\xF0\x42\x18\x42\x71\x2E\x0C\xB9\x53\xBA\xB9\x6B\x82\xCD\xF5\xE0\x93\x8D\xBC\xD1");

    EXPECT_EQ(Utils::b2s(priv1->deriveSharedSecret(*publ2)),expected_derPriv1Pub2);
    EXPECT_EQ(Utils::b2s(priv2->deriveSharedSecret(*publ1)),expected_derPriv1Pub2);
    EXPECT_EQ(Utils::b2s(priv3->deriveSharedSecret(*publ4)),expected_derPriv3Pub4);
    EXPECT_EQ(Utils::b2s(priv4->deriveSharedSecret(*publ3)),expected_derPriv4Pub3);
}

} // namespace ecc
} // namespace cryptoservice
} // namespace privmx
