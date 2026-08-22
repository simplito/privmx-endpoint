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
#include "ECDHE.hpp"


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

TEST(PrivateKeyTest, KeyDerivationEcdheTests) {
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

    const string expected_ecdhe12_enc("\x11\x5F\x05\xC6\x0D\x54\xDB\x1D\xAD\x83\x07\x55\x12\x72\x3F\x34\xF9\x3B\x82\x40\xC3\x30\x58\x97\xD3\xFD\xDD\x85\xFA\x24\x5E\x34");
    const string expected_ecdhe21_enc("\x11\x5F\x05\xC6\x0D\x54\xDB\x1D\xAD\x83\x07\x55\x12\x72\x3F\x34\xF9\x3B\x82\x40\xC3\x30\x58\x97\xD3\xFD\xDD\x85\xFA\x24\x5E\x34");
    const string expected_ecdhe34_enc("\x0F\x47\xBD\xE4\x90\x06\xCC\x40\x67\x53\x32\x88\xF0\x42\x18\x42\x71\x2E\x0C\xB9\x53\xBA\xB9\x6B\x82\xCD\xF5\xE0\x93\x8D\xBC\xD1");
    const string expected_ecdhe43_enc("\x0F\x47\xBD\xE4\x90\x06\xCC\x40\x67\x53\x32\x88\xF0\x42\x18\x42\x71\x2E\x0C\xB9\x53\xBA\xB9\x6B\x82\xCD\xF5\xE0\x93\x8D\xBC\xD1");

    ECDHE ecdhe12(priv1, publ2);
    ECDHE ecdhe21(priv2, publ1);
    ECDHE ecdhe34(priv3, publ4);
    ECDHE ecdhe43(priv4, publ3);

    EXPECT_EQ(ecdhe12.getSecret(), expected_ecdhe12_enc);
    EXPECT_EQ(ecdhe21.getSecret(), expected_ecdhe21_enc);
    EXPECT_EQ(ecdhe34.getSecret(), expected_ecdhe34_enc);
    EXPECT_EQ(ecdhe43.getSecret(), expected_ecdhe43_enc);

}

} // namespace ecc
} // namespace cryptoservice
} // namespace privmx
