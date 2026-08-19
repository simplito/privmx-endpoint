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

TEST(PublicKeyTest, ExportBasicTests) {
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

    PrivateKey priv1 = PrivateKey::fromWIF(wif1);
    PrivateKey priv2 = PrivateKey::fromWIF(wif2);
    PrivateKey priv3 = PrivateKey::fromWIF(wif3);
    PrivateKey priv4 = PrivateKey::fromWIF(wif4);

    // EXPECT_EQ(priv1.getPrivateEncKey(), expected_priv1);
    // EXPECT_EQ(priv1.toWIF(), wif1);
    // EXPECT_EQ(priv2.getPrivateEncKey(), expected_priv2);
    // EXPECT_EQ(priv2.toWIF(), wif2);
    // EXPECT_EQ(priv3.getPrivateEncKey(), expected_priv3);
    // EXPECT_EQ(priv3.toWIF(), wif3);
    // EXPECT_EQ(priv4.getPrivateEncKey(), expected_priv4);
    // EXPECT_EQ(priv4.toWIF(), wif4);

    PublicKey publ1 = priv1.getPublicKey();
    PublicKey publ2 = priv2.getPublicKey();
    PublicKey publ3 = priv3.getPublicKey();
    PublicKey publ4 = priv4.getPublicKey();

    EXPECT_EQ(publ1.toDER(), expected_publ1Der);
    EXPECT_EQ(publ2.toDER(), expected_publ2Der);
    EXPECT_EQ(publ3.toDER(), expected_publ3Der);
    EXPECT_EQ(publ4.toDER(), expected_publ4Der);

    EXPECT_EQ(publ1.toBase58DER(), expected_publ1Base58Der);
    EXPECT_EQ(publ2.toBase58DER(), expected_publ2Base58Der);
    EXPECT_EQ(publ3.toBase58DER(), expected_publ3Base58Der);
    EXPECT_EQ(publ4.toBase58DER(), expected_publ4Base58Der);

    EXPECT_EQ(publ1.toBase58Address(), expected_publ1Base58DerAddr);
    EXPECT_EQ(publ2.toBase58Address(), expected_publ2Base58DerAddr);
    EXPECT_EQ(publ3.toBase58Address(), expected_publ3Base58DerAddr);
    EXPECT_EQ(publ4.toBase58Address(), expected_publ4Base58DerAddr);

    PublicKey publ1fd = PublicKey::fromDER(expected_publ1Der);
    PublicKey publ2fd = PublicKey::fromDER(expected_publ2Der);
    PublicKey publ3fd = PublicKey::fromDER(expected_publ3Der);
    PublicKey publ4fd = PublicKey::fromDER(expected_publ4Der);

    EXPECT_EQ(publ1fd.toDER(), expected_publ1Der);
    EXPECT_EQ(publ2fd.toDER(), expected_publ2Der);
    EXPECT_EQ(publ3fd.toDER(), expected_publ3Der);
    EXPECT_EQ(publ4fd.toDER(), expected_publ4Der);
    
    PublicKey publ1fb = PublicKey::fromBase58DER(expected_publ1Base58Der);
    PublicKey publ2fb = PublicKey::fromBase58DER(expected_publ2Base58Der);
    PublicKey publ3fb = PublicKey::fromBase58DER(expected_publ3Base58Der);
    PublicKey publ4fb = PublicKey::fromBase58DER(expected_publ4Base58Der);

    EXPECT_EQ(publ1fb.toBase58DER(), expected_publ1Base58Der);
    EXPECT_EQ(publ2fb.toBase58DER(), expected_publ2Base58Der);
    EXPECT_EQ(publ3fb.toBase58DER(), expected_publ3Base58Der);
    EXPECT_EQ(publ4fb.toBase58DER(), expected_publ4Base58Der);

    EXPECT_EQ(publ1fd.toBase58DER(), expected_publ1Base58Der);
    EXPECT_EQ(publ2fd.toBase58DER(), expected_publ2Base58Der);
    EXPECT_EQ(publ3fd.toBase58DER(), expected_publ3Base58Der);
    EXPECT_EQ(publ4fd.toBase58DER(), expected_publ4Base58Der);

    EXPECT_EQ(publ1fb.toDER(), expected_publ1Der);
    EXPECT_EQ(publ2fb.toDER(), expected_publ2Der);
    EXPECT_EQ(publ3fb.toDER(), expected_publ3Der);
    EXPECT_EQ(publ4fb.toDER(), expected_publ4Der);
}

} // namespace ecc
} // namespace cryptoservice
} // namespace privmx
