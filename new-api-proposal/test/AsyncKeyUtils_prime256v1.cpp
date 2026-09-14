#include <string>
#include <gtest/gtest.h>

// #include <privmx/crypto/ecc/PrivateKey.hpp>
// #include <privmx/utils/Utils.hpp>

// #include "PrivateKey.hpp"

// #include "PrivateKey2.hpp"
// #include "PublicKey2.hpp"

// #include "PrivateKey.hpp"
// #include "PublicKey.hpp"

#include "AsyncKeyUtils.hpp"

#include "Utils.hpp"

using namespace std;
// using privmx::cryptoservice::ecc::AsyncKeyUtils;
using privmx::cryptoservice::AsyncKeyUtils;
using privmx::cryptoservice::ecc::Utils;


namespace privmx {
namespace cryptoservice {
// namespace ecc {

/*
 * Fixed data to represent the private and public key for "prime256v1" ("P-256") curve.
 * (sample data from page https://docs.openssl.org/master/man3/EVP_PKEY_fromdata/)
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


TEST(AsyncKeyUtilsTest, prime256v1ImportExport) {
    Bytes privPart(priv_data, priv_data + sizeof priv_data);
    Bytes pubPart(pub_data, pub_data + sizeof pub_data);
    Bytes bothParts(pub_data, pub_data + sizeof pub_data);
    bothParts.insert(bothParts.end(), privPart.begin(), privPart.end());
    EXPECT_EQ(sizeof priv_data, privPart.size());
    EXPECT_EQ(sizeof pub_data, pubPart.size());
    EXPECT_EQ(65+32, bothParts.size());

    // import and export key public part
    auto keyPub = AsyncKeyUtils::fromRawP256("prime256v1", pubPart);
    Bytes rawPublic1 = AsyncKeyUtils::toRaw(AsymAlg::prime256v1, keyPub, false);
    EXPECT_EQ(sizeof pub_data, rawPublic1.size());
    EXPECT_EQ(pubPart, rawPublic1);
    
    // import and export both key public and private parts
    auto keyPriv = AsyncKeyUtils::fromRawP256("prime256v1", bothParts);
    Bytes rawPrivate = AsyncKeyUtils::toRaw(AsymAlg::prime256v1, keyPriv);
    EXPECT_EQ(65+32, bothParts.size());
    EXPECT_EQ(bothParts, rawPrivate);
}

TEST(AsyncKeyUtilsTest, prime256v1CalculatePublicPart) {
    Bytes privPart(priv_data, priv_data + sizeof priv_data);
    Bytes pubPart(pub_data, pub_data + sizeof pub_data);
    Bytes bothParts(pub_data, pub_data + sizeof pub_data);
    bothParts.insert(bothParts.end(), privPart.begin(), privPart.end());
    EXPECT_EQ(sizeof priv_data, privPart.size());
    EXPECT_EQ(sizeof pub_data, pubPart.size());
    EXPECT_EQ(65+32, bothParts.size());

    // calculate and inject public part to private-only key
    auto keyPrivOnly = AsyncKeyUtils::fromRawP256PrivateOnly("prime256v1", privPart);
    Bytes computedPublic = AsyncKeyUtils::GetPubKeyFromPrivKey(keyPrivOnly.get(), false, true);
    Bytes rawPublicInjected = AsyncKeyUtils::toRaw(AsymAlg::prime256v1, keyPrivOnly, false);
    Bytes rawPrivateCombined = AsyncKeyUtils::toRaw(AsymAlg::prime256v1, keyPrivOnly, true);

    EXPECT_EQ(sizeof pub_data, computedPublic.size());
    EXPECT_EQ(sizeof pub_data, rawPublicInjected.size());
    EXPECT_EQ(65 + 32, rawPrivateCombined.size());

    EXPECT_EQ(pubPart, computedPublic);
    EXPECT_EQ(pubPart, rawPublicInjected);
    EXPECT_EQ(bothParts, rawPrivateCombined);
}

TEST(AsyncKeyUtilsTest, prime256v1GenerateSignVerify) {
    auto key1 = AsyncKeyUtils::getRandomKey(AsymAlg::prime256v1);
    Bytes key1pubBytes = AsyncKeyUtils::toRaw(AsymAlg::prime256v1, key1, false);
    auto key1pub = AsyncKeyUtils::fromRawP256("prime256v1", key1pubBytes);

    auto key2 = AsyncKeyUtils::getRandomKey(AsymAlg::prime256v1);
    Bytes key2pubBytes = AsyncKeyUtils::toRaw(AsymAlg::prime256v1, key2, false);
    auto key2pub = AsyncKeyUtils::fromRawP256("prime256v1", key2pubBytes);

    Bytes message = Utils::s2b("Message to sign");

    // Signing
    Bytes sign1 = AsyncKeyUtils::sign(AsymAlg::prime256v1, key1.get(), message);
    Bytes sign2 = AsyncKeyUtils::sign(AsymAlg::prime256v1, key2.get(), message);

    // Verifying - positive
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::prime256v1, key1.get(), message, sign1));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::prime256v1, key1pub.get(), message, sign1));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::prime256v1, key2.get(), message, sign2));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::prime256v1, key2pub.get(), message, sign2));

    // Verifying - negative
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::prime256v1, key1.get(), message, sign2));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::prime256v1, key1pub.get(), message, sign2));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::prime256v1, key2.get(), message, sign1));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::prime256v1, key2pub.get(), message, sign1));

}

// } // namespace ecc
} // namespace cryptoservice
} // namespace privmx
