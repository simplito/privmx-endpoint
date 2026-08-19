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

using namespace std;

namespace privmx {
namespace cryptoservice {
namespace ecc {

TEST(PublicKeyTest, ExportProviderTests) {
    const string wif1("L1YwTwAr8dQCBzfmXBzh6ggBkYbLuu15Tc7s4bajrRNDbsogs9a5");
    const string wif2("KwDzTrBejZw91hSpkoauVYnjgkm64DAb3UX1QBCRjf5BryiVK6jk");
    const string wif3("KwDiK7diMWJYFDV6pPbQ8BzgWznPa4evLqKwLncDpeMrEZA5E2Xp");
    const string wif4("KwDkPqYKx8R2zEPTP6QnPLsvYSwsqeCJKHsJ6GWncC3r4CaqViRB");

    const string expected_priv1("\x81\x3d\xe0\x0e\xb4\x3c\x22\x7e\xaf\x82\x47\x40\xbc\xee\x66\xf8\xb8\xe4\xc0\x83\x83\x34\x83\x65\x8c\x8c\x65\xe7\xd9\xcd\x76\xc9", 32);
    const string expected_priv2("\x00\x24\xf6\xbb\xb1\x0a\x74\xd9\x0a\xeb\xbc\xc3\xf4\xf1\x8a\x86\xda\xb8\x6c\x81\x51\x3b\x4a\x3b\x9d\x28\xe8\x26\xd6\xa7\x9a\x97", 32);
    const string expected_priv3("\x00\x00\x4a\xbc\x31\xdf\x4a\x0e\xc4\x9a\xec\x9e\xfa\x6d\xce\x2e\x6b\x3d\xa3\x99\x85\x6f\x13\xd0\xef\x56\x07\x6b\x62\x84\xab\x4d", 32);
    const string expected_priv4("\x00\x05\x04\x9f\x90\xde\x17\x9b\xb2\x6d\x66\x90\xdc\x68\x2d\xed\xb7\xcd\xa5\x03\x0b\x93\x7b\xd8\x7c\x65\x36\xdd\x46\x2a\x58\xf3", 32);

   const string expected_publ1Der("\x02\x83\xDC\x94\x5E\xBC\xA5\x55\xC3\x89\xDB\xEE\x2B\x35\x88\x13\xBD\x88\x29\x9C\xAF\xC3\x77\xC4\x36\x0C\x42\x78\x8C\xA6\x81\xC8\xB6");
   const string expected_publ2Der("\x03\x3F\x9C\xDA\x80\x59\x6E\x64\xE1\xE9\xC3\x1F\x62\x7B\x11\xDD\x7B\xD1\xA7\x4D\x83\x59\x63\xA6\x2A\xE5\x5A\x8C\xB3\x1E\x6F\xD3\xF9");
   const string expected_publ3Der("\x02\x80\x4D\xD8\xE9\x3C\xC9\xBF\xEB\x4D\xA3\x72\x26\x99\xD1\x32\x95\x51\x61\xD2\xDD\x57\xCD\x31\x0E\x28\x67\x31\x18\xD9\x44\x16\x38");
   const string expected_publ4Der("\x03\xF5\xC7\x61\x87\x5B\xA5\x97\x0C\x15\x24\x26\xD9\xA5\x0A\x25\xC7\xDB\xD9\xB6\xF5\xC0\xFE\x09\xA3\x1B\x64\x37\x88\xFA\x81\x9F\xC0");

   const string expected_publ1Base58Der("5tZaish983y4RHL2oEM3zvoRTEMwp3afQrQQjwe4nE7Pp74z6f");
   const string expected_publ2Base58Der("7KFRyEpfygeSJazhH9EoKTTinQtSG5r6fFk7JDBwEQbCegJdkt");
   const string expected_publ3Base58Der("5rzi6pcWXAcnH6uPtjMFTEuFDfJPWdRVDQmTN35wtNLX5ud3sj");
   const string expected_publ4Base58Der("8hUcwRXfSaa3k1KuewbNcgn83CzLKs3RpH6fZVVyLBS3E8J5T6");

   const string expected_publ1Base58DerAddr("1CD4JwhhEYZDqDgV8dVAhT3uJXGiZV5XZv");
   const string expected_publ2Base58DerAddr("1JgPAW1471FqP16J6nhz52kpj5z5EgudWA");
   const string expected_publ3Base58DerAddr("1EzdjPPUt9s7onJbS4SrG8PyfAordH3Grf");
   const string expected_publ4Base58DerAddr("1F3oot84D8Zrk218wXrrqwpN3Dpx4aptNy");


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

    std::shared_ptr<IPublicKey> publ1d = CryptoProviderRegistry::get().importPublicKey(
        Utils::s2b(expected_publ1Der), KeyFormat::Der, AsymAlg::EccSecp256k1);
    std::shared_ptr<IPublicKey> publ2d = CryptoProviderRegistry::get().importPublicKey(
        Utils::s2b(expected_publ2Der), KeyFormat::Der, AsymAlg::EccSecp256k1);
    std::shared_ptr<IPublicKey> publ3d = CryptoProviderRegistry::get().importPublicKey(
        Utils::s2b(expected_publ3Der), KeyFormat::Der, AsymAlg::EccSecp256k1);
    std::shared_ptr<IPublicKey> publ4d = CryptoProviderRegistry::get().importPublicKey(
        Utils::s2b(expected_publ4Der), KeyFormat::Der, AsymAlg::EccSecp256k1);

    std::shared_ptr<IPublicKey> publ1b = CryptoProviderRegistry::get().importPublicKey(
        Utils::s2b(expected_publ1Base58Der), KeyFormat::Base58Der, AsymAlg::EccSecp256k1);
    std::shared_ptr<IPublicKey> publ2b = CryptoProviderRegistry::get().importPublicKey(
        Utils::s2b(expected_publ2Base58Der), KeyFormat::Base58Der, AsymAlg::EccSecp256k1);
    std::shared_ptr<IPublicKey> publ3b = CryptoProviderRegistry::get().importPublicKey(
        Utils::s2b(expected_publ3Base58Der), KeyFormat::Base58Der, AsymAlg::EccSecp256k1);
    std::shared_ptr<IPublicKey> publ4b = CryptoProviderRegistry::get().importPublicKey(
        Utils::s2b(expected_publ4Base58Der), KeyFormat::Base58Der, AsymAlg::EccSecp256k1);

    EXPECT_EQ(Utils::b2s(publ1->export_(KeyFormat::Der)), expected_publ1Der);
    EXPECT_EQ(Utils::b2s(publ2->export_(KeyFormat::Der)), expected_publ2Der);
    EXPECT_EQ(Utils::b2s(publ3->export_(KeyFormat::Der)), expected_publ3Der);
    EXPECT_EQ(Utils::b2s(publ4->export_(KeyFormat::Der)), expected_publ4Der);

    EXPECT_EQ(Utils::b2s(publ1->export_(KeyFormat::Base58Der)), expected_publ1Base58Der);
    EXPECT_EQ(Utils::b2s(publ2->export_(KeyFormat::Base58Der)), expected_publ2Base58Der);
    EXPECT_EQ(Utils::b2s(publ3->export_(KeyFormat::Base58Der)), expected_publ3Base58Der);
    EXPECT_EQ(Utils::b2s(publ4->export_(KeyFormat::Base58Der)), expected_publ4Base58Der);

    EXPECT_EQ(Utils::b2s(publ1->export_(KeyFormat::Base58DerAddr)), expected_publ1Base58DerAddr);
    EXPECT_EQ(Utils::b2s(publ2->export_(KeyFormat::Base58DerAddr)), expected_publ2Base58DerAddr);
    EXPECT_EQ(Utils::b2s(publ3->export_(KeyFormat::Base58DerAddr)), expected_publ3Base58DerAddr);
    EXPECT_EQ(Utils::b2s(publ4->export_(KeyFormat::Base58DerAddr)), expected_publ4Base58DerAddr);

    EXPECT_EQ(Utils::b2s(publ1b->export_(KeyFormat::Base58Der)), expected_publ1Base58Der);
    EXPECT_EQ(Utils::b2s(publ2b->export_(KeyFormat::Base58Der)), expected_publ2Base58Der);
    EXPECT_EQ(Utils::b2s(publ3b->export_(KeyFormat::Base58Der)), expected_publ3Base58Der);
    EXPECT_EQ(Utils::b2s(publ4b->export_(KeyFormat::Base58Der)), expected_publ4Base58Der);

    EXPECT_EQ(Utils::b2s(publ1d->export_(KeyFormat::Der)), expected_publ1Der);
    EXPECT_EQ(Utils::b2s(publ2d->export_(KeyFormat::Der)), expected_publ2Der);
    EXPECT_EQ(Utils::b2s(publ3d->export_(KeyFormat::Der)), expected_publ3Der);
    EXPECT_EQ(Utils::b2s(publ4d->export_(KeyFormat::Der)), expected_publ4Der);
    
}

} // namespace ecc
} // namespace cryptoservice
} // namespace privmx
