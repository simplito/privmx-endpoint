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
 * Fixed data to represent the private and public key for "secp256k1" curve.
 * (sample data from existing tests)
 */
const unsigned char priv_data_1[] = {
	0x81, 0x3d, 0xe0, 0x0e, 0xb4, 0x3c, 0x22, 0x7e,
	0xaf, 0x82, 0x47, 0x40, 0xbc, 0xee, 0x66, 0xf8,
	0xb8, 0xe4, 0xc0, 0x83, 0x83, 0x34, 0x83, 0x65,
	0x8c, 0x8c, 0x65, 0xe7, 0xd9, 0xcd, 0x76, 0xc9
};
const unsigned char priv_data_2[] = {
	0x00, 0x24, 0xf6, 0xbb, 0xb1, 0x0a, 0x74, 0xd9, 
    0x0a, 0xeb, 0xbc, 0xc3, 0xf4, 0xf1, 0x8a, 0x86, 
    0xda, 0xb8, 0x6c, 0x81, 0x51, 0x3b, 0x4a, 0x3b, 
    0x9d, 0x28, 0xe8, 0x26, 0xd6, 0xa7, 0x9a, 0x97
};
const unsigned char priv_data_3[] = {
	0x00, 0x00, 0x4a, 0xbc, 0x31, 0xdf, 0x4a, 0x0e, 
    0xc4, 0x9a, 0xec, 0x9e, 0xfa, 0x6d, 0xce, 0x2e, 
    0x6b, 0x3d, 0xa3, 0x99, 0x85, 0x6f, 0x13, 0xd0, 
    0xef, 0x56, 0x07, 0x6b, 0x62, 0x84, 0xab, 0x4d
};
const unsigned char priv_data_4[] = {
    0x00, 0x05, 0x04, 0x9f, 0x90, 0xde, 0x17, 0x9b, 
    0xb2, 0x6d, 0x66, 0x90, 0xdc, 0x68, 0x2d, 0xed, 
    0xb7, 0xcd, 0xa5, 0x03, 0x0b, 0x93, 0x7b, 0xd8, 
    0x7c, 0x65, 0x36, 0xdd, 0x46, 0x2a, 0x58, 0xf3
};

/* UNCOMPRESSED FORMAT */
const unsigned char pub_data_1_unc[] = {
    POINT_CONVERSION_UNCOMPRESSED,
	0x83, 0xdc, 0x94, 0x5e, 0xbc, 0xa5, 0x55, 0xc3,
	0x89, 0xdb, 0xee, 0x2b, 0x35, 0x88, 0x13, 0xbd,
	0x88, 0x29, 0x9c, 0xaf, 0xc3, 0x77, 0xc4, 0x36,
	0x0c, 0x42, 0x78, 0x8c, 0xa6, 0x81, 0xc8, 0xb6,
	0x13, 0xd4, 0x9b, 0x00, 0x8c, 0x13, 0x13, 0xc5,
	0x37, 0x89, 0x1e, 0xf4, 0xd1, 0x62, 0x73, 0x4e,
	0xf7, 0x98, 0x8e, 0x88, 0x70, 0x8b, 0xe3, 0x6d,
	0xdb, 0x68, 0x06, 0x0f, 0x11, 0xc6, 0xfc, 0x52
};
const unsigned char pub_data_2_unc[] = {
    POINT_CONVERSION_UNCOMPRESSED,
	0x3f, 0x9c, 0xda, 0x80, 0x59, 0x6e, 0x64, 0xe1,
	0xe9, 0xc3, 0x1f, 0x62, 0x7b, 0x11, 0xdd, 0x7b,
	0xd1, 0xa7, 0x4d, 0x83, 0x59, 0x63, 0xa6, 0x2a,
	0xe5, 0x5a, 0x8c, 0xb3, 0x1e, 0x6f, 0xd3, 0xf9,
	0x86, 0xd2, 0x28, 0xcd, 0x88, 0xa9, 0x21, 0xc9,
	0xb7, 0xa7, 0x5c, 0x84, 0x6f, 0x70, 0x17, 0x05,
	0xfc, 0xd5, 0xfe, 0xd1, 0x79, 0x6e, 0xfc, 0x81,
	0xfe, 0xe8, 0x18, 0x6b, 0x6f, 0xc0, 0xd3, 0xf5
};
const unsigned char pub_data_3_unc[] = {
    POINT_CONVERSION_UNCOMPRESSED,
    0x80, 0x4d, 0xd8, 0xe9, 0x3c, 0xc9, 0xbf, 0xeb,
	0x4d, 0xa3, 0x72, 0x26, 0x99, 0xd1, 0x32, 0x95,
	0x51, 0x61, 0xd2, 0xdd, 0x57, 0xcd, 0x31, 0x0e,
	0x28, 0x67, 0x31, 0x18, 0xd9, 0x44, 0x16, 0x38,
	0x67, 0x09, 0xce, 0x7d, 0xe6, 0xf0, 0x84, 0x0b,
	0x9b, 0xa0, 0xb7, 0xcc, 0xc1, 0xb3, 0x78, 0xa4,
	0xfa, 0x29, 0xa9, 0x7b, 0x35, 0x8a, 0x82, 0xf3,
	0x09, 0x0a, 0x2b, 0xd3, 0x3f, 0xcb, 0xb3, 0x90
};
const unsigned char pub_data_4_unc[] = {
    POINT_CONVERSION_UNCOMPRESSED,
	0xf5, 0xc7, 0x61, 0x87, 0x5b, 0xa5, 0x97, 0x0c,
	0x15, 0x24, 0x26, 0xd9, 0xa5, 0x0a, 0x25, 0xc7,
	0xdb, 0xd9, 0xb6, 0xf5, 0xc0, 0xfe, 0x09, 0xa3,
	0x1b, 0x64, 0x37, 0x88, 0xfa, 0x81, 0x9f, 0xc0,
	0xfe, 0xbf, 0xde, 0x44, 0x53, 0x9b, 0x4e, 0x9b,
	0x29, 0x34, 0xa8, 0xee, 0x57, 0x6e, 0xf1, 0x14,
	0xba, 0x56, 0xd6, 0x2e, 0xd9, 0x0e, 0x23, 0x20,
	0x24, 0xc9, 0xb8, 0xda, 0xb4, 0x58, 0x0e, 0xb1    
};

/* COMPRESSED FORMAT */
const unsigned char pub_data_1_compr[] = {
    0x02,
	0x83, 0xdc, 0x94, 0x5e, 0xbc, 0xa5, 0x55, 0xc3,
	0x89, 0xdb, 0xee, 0x2b, 0x35, 0x88, 0x13, 0xbd,
	0x88, 0x29, 0x9c, 0xaf, 0xc3, 0x77, 0xc4, 0x36,
	0x0c, 0x42, 0x78, 0x8c, 0xa6, 0x81, 0xc8, 0xb6
};
const unsigned char pub_data_2_compr[] = {
	0x03,
	0x3f, 0x9c, 0xda, 0x80, 0x59, 0x6e, 0x64, 0xe1,
	0xe9, 0xc3, 0x1f, 0x62, 0x7b, 0x11, 0xdd, 0x7b,
	0xd1, 0xa7, 0x4d, 0x83, 0x59, 0x63, 0xa6, 0x2a,
	0xe5, 0x5a, 0x8c, 0xb3, 0x1e, 0x6f, 0xd3, 0xf9
};
const unsigned char pub_data_3_compr[] = {
	0x02,
    0x80, 0x4d, 0xd8, 0xe9, 0x3c, 0xc9, 0xbf, 0xeb,
	0x4d, 0xa3, 0x72, 0x26, 0x99, 0xd1, 0x32, 0x95,
	0x51, 0x61, 0xd2, 0xdd, 0x57, 0xcd, 0x31, 0x0e,
	0x28, 0x67, 0x31, 0x18, 0xd9, 0x44, 0x16, 0x38
};
const unsigned char pub_data_4_compr[] = {
	0x03,
	0xf5, 0xc7, 0x61, 0x87, 0x5b, 0xa5, 0x97, 0x0c,
	0x15, 0x24, 0x26, 0xd9, 0xa5, 0x0a, 0x25, 0xc7,
	0xdb, 0xd9, 0xb6, 0xf5, 0xc0, 0xfe, 0x09, 0xa3,
	0x1b, 0x64, 0x37, 0x88, 0xfa, 0x81, 0x9f, 0xc0
};

TEST(AsyncKeyUtilsTest, secp256k1ImportExport1) {
    Bytes privPart1(priv_data_1, priv_data_1 + sizeof priv_data_1);
    Bytes pubPart1(pub_data_1_unc, pub_data_1_unc + sizeof pub_data_1_unc);
    Bytes bothParts1(pub_data_1_unc, pub_data_1_unc + sizeof pub_data_1_unc);
    bothParts1.insert(bothParts1.end(), privPart1.begin(), privPart1.end());
    EXPECT_EQ(sizeof priv_data_1, privPart1.size());
    EXPECT_EQ(sizeof pub_data_1_unc, pubPart1.size());
    EXPECT_EQ(65+32, bothParts1.size());

    // import and export key public part
    auto key1Pub = AsyncKeyUtils::fromRawP256("secp256k1", pubPart1);
    Bytes rawPublic1 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key1Pub, false);
    EXPECT_EQ(sizeof pub_data_1_unc, rawPublic1.size());
    EXPECT_EQ(pubPart1, rawPublic1);
    
    // import and export both key public and private parts
    auto key1Priv = AsyncKeyUtils::fromRawP256("secp256k1", bothParts1);
    Bytes rawPrivate1 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key1Priv);
    EXPECT_EQ(65+32, bothParts1.size());
    EXPECT_EQ(bothParts1, rawPrivate1);
}

TEST(AsyncKeyUtilsTest, secp256k1CalculatePublicPart1) {
    Bytes privPart1(priv_data_1, priv_data_1 + sizeof priv_data_1);
    Bytes pubPart1(pub_data_1_unc, pub_data_1_unc + sizeof pub_data_1_unc);
    Bytes bothParts1(pub_data_1_unc, pub_data_1_unc + sizeof pub_data_1_unc);
    bothParts1.insert(bothParts1.end(), privPart1.begin(), privPart1.end());
    EXPECT_EQ(sizeof priv_data_1, privPart1.size());
    EXPECT_EQ(sizeof pub_data_1_unc, pubPart1.size());
    EXPECT_EQ(65+32, bothParts1.size());

    // calculate and inject public part to private-only key
    auto key1PrivOnly = AsyncKeyUtils::fromRawP256PrivateOnly("secp256k1", privPart1);
    Bytes computedPublic1 = AsyncKeyUtils::GetPubKeyFromPrivKey(key1PrivOnly.get(), false, true);
    Bytes rawPublicInjected1 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key1PrivOnly, false);
    Bytes rawPrivateCombined1 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key1PrivOnly, true);

    EXPECT_EQ(sizeof pub_data_1_unc, computedPublic1.size());
    EXPECT_EQ(sizeof pub_data_1_unc, rawPublicInjected1.size());
    EXPECT_EQ(65 + 32, rawPrivateCombined1.size());

    EXPECT_EQ(pubPart1, computedPublic1);
    EXPECT_EQ(pubPart1, rawPublicInjected1);
    EXPECT_EQ(bothParts1, rawPrivateCombined1);

    // calculate public part in compressed form
    Bytes pubPart1Compr(pub_data_1_compr, pub_data_1_compr + sizeof pub_data_1_compr);
    Bytes computedPublic1Compr = AsyncKeyUtils::GetPubKeyFromPrivKey(key1PrivOnly.get(), true);
    EXPECT_EQ(sizeof pub_data_1_compr, computedPublic1Compr.size());
    EXPECT_EQ(pubPart1Compr, computedPublic1Compr);
}

TEST(AsyncKeyUtilsTest, secp256k1ImportExport2) {
    Bytes privPart2(priv_data_2, priv_data_2 + sizeof priv_data_2);
    Bytes pubPart2(pub_data_2_unc, pub_data_2_unc + sizeof pub_data_2_unc);
    Bytes bothParts2(pub_data_2_unc, pub_data_2_unc + sizeof pub_data_2_unc);
    bothParts2.insert(bothParts2.end(), privPart2.begin(), privPart2.end());
    EXPECT_EQ(sizeof priv_data_2, privPart2.size());
    EXPECT_EQ(sizeof pub_data_2_unc, pubPart2.size());
    EXPECT_EQ(65+32, bothParts2.size());

    // import and export key public part
    auto key2Pub = AsyncKeyUtils::fromRawP256("secp256k1", pubPart2);
    Bytes rawPublic2 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key2Pub, false);
    EXPECT_EQ(sizeof pub_data_2_unc, rawPublic2.size());
    EXPECT_EQ(pubPart2, rawPublic2);
    
    // import and export both key public and private parts
    auto key2Priv = AsyncKeyUtils::fromRawP256("secp256k1", bothParts2);
    Bytes rawPrivate2 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key2Priv);
    EXPECT_EQ(65+32, bothParts2.size());
    EXPECT_EQ(bothParts2, rawPrivate2);
}

TEST(AsyncKeyUtilsTest, secp256k1CalculatePublicPart2) {
    Bytes privPart2(priv_data_2, priv_data_2 + sizeof priv_data_2);
    Bytes pubPart2(pub_data_2_unc, pub_data_2_unc + sizeof pub_data_2_unc);
    Bytes bothParts2(pub_data_2_unc, pub_data_2_unc + sizeof pub_data_2_unc);
    bothParts2.insert(bothParts2.end(), privPart2.begin(), privPart2.end());
    EXPECT_EQ(sizeof priv_data_2, privPart2.size());
    EXPECT_EQ(sizeof pub_data_2_unc, pubPart2.size());
    EXPECT_EQ(65+32, bothParts2.size());

    // calculate and inject public part to private-only key
    auto key2PrivOnly = AsyncKeyUtils::fromRawP256PrivateOnly("secp256k1", privPart2);
    Bytes computedPublic2 = AsyncKeyUtils::GetPubKeyFromPrivKey(key2PrivOnly.get(), false, true);
    Bytes rawPublicInjected2 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key2PrivOnly, false);
    Bytes rawPrivateCombined2 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key2PrivOnly, true);

    EXPECT_EQ(sizeof pub_data_2_unc, computedPublic2.size());
    EXPECT_EQ(sizeof pub_data_2_unc, rawPublicInjected2.size());
    EXPECT_EQ(65 + 32, rawPrivateCombined2.size());

    EXPECT_EQ(pubPart2, computedPublic2);
    EXPECT_EQ(pubPart2, rawPublicInjected2);
    EXPECT_EQ(bothParts2, rawPrivateCombined2);

    // calculate public part in compressed form
    Bytes pubPart2Compr(pub_data_2_compr, pub_data_2_compr + sizeof pub_data_2_compr);
    Bytes computedPublic2Compr = AsyncKeyUtils::GetPubKeyFromPrivKey(key2PrivOnly.get(), true);
    EXPECT_EQ(sizeof pub_data_2_compr, computedPublic2Compr.size());
    EXPECT_EQ(pubPart2Compr, computedPublic2Compr);
}


TEST(AsyncKeyUtilsTest, secp256k1ImportExport3) {
    Bytes privPart3(priv_data_3, priv_data_3 + sizeof priv_data_3);
    Bytes pubPart3(pub_data_3_unc, pub_data_3_unc + sizeof pub_data_3_unc);
    Bytes bothParts3(pub_data_3_unc, pub_data_3_unc + sizeof pub_data_3_unc);
    bothParts3.insert(bothParts3.end(), privPart3.begin(), privPart3.end());
    EXPECT_EQ(sizeof priv_data_3, privPart3.size());
    EXPECT_EQ(sizeof pub_data_3_unc, pubPart3.size());
    EXPECT_EQ(65+32, bothParts3.size());

    // import and export key public part
    auto key3Pub = AsyncKeyUtils::fromRawP256("secp256k1", pubPart3);
    Bytes rawPublic3 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key3Pub, false);
    EXPECT_EQ(sizeof pub_data_3_unc, rawPublic3.size());
    EXPECT_EQ(pubPart3, rawPublic3);
    
    // import and export both key public and private parts
    auto key3Priv = AsyncKeyUtils::fromRawP256("secp256k1", bothParts3);
    Bytes rawPrivate3 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key3Priv);
    EXPECT_EQ(65+32, bothParts3.size());
    EXPECT_EQ(bothParts3, rawPrivate3);
}

TEST(AsyncKeyUtilsTest, secp256k1CalculatePublicPart3) {
    Bytes privPart3(priv_data_3, priv_data_3 + sizeof priv_data_3);
    Bytes pubPart3(pub_data_3_unc, pub_data_3_unc + sizeof pub_data_3_unc);
    Bytes bothParts3(pub_data_3_unc, pub_data_3_unc + sizeof pub_data_3_unc);
    bothParts3.insert(bothParts3.end(), privPart3.begin(), privPart3.end());
    EXPECT_EQ(sizeof priv_data_3, privPart3.size());
    EXPECT_EQ(sizeof pub_data_3_unc, pubPart3.size());
    EXPECT_EQ(65+32, bothParts3.size());

    // calculate and inject public part to private-only key
    auto key3PrivOnly = AsyncKeyUtils::fromRawP256PrivateOnly("secp256k1", privPart3);
    Bytes computedPublic3 = AsyncKeyUtils::GetPubKeyFromPrivKey(key3PrivOnly.get(), false, true);
    Bytes rawPublicInjected3 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key3PrivOnly, false);
    Bytes rawPrivateCombined3 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key3PrivOnly, true);

    EXPECT_EQ(sizeof pub_data_3_unc, computedPublic3.size());
    EXPECT_EQ(sizeof pub_data_3_unc, rawPublicInjected3.size());
    EXPECT_EQ(65 + 32, rawPrivateCombined3.size());

    EXPECT_EQ(pubPart3, computedPublic3);
    EXPECT_EQ(pubPart3, rawPublicInjected3);
    EXPECT_EQ(bothParts3, rawPrivateCombined3);

    // calculate public part in compressed form
    Bytes pubPart3Compr(pub_data_3_compr, pub_data_3_compr + sizeof pub_data_3_compr);
    Bytes computedPublic3Compr = AsyncKeyUtils::GetPubKeyFromPrivKey(key3PrivOnly.get(), true);
    EXPECT_EQ(sizeof pub_data_3_compr, computedPublic3Compr.size());
    EXPECT_EQ(pubPart3Compr, computedPublic3Compr);
}

TEST(AsyncKeyUtilsTest, secp256k1ImportExport4) {
    Bytes privPart4(priv_data_4, priv_data_4 + sizeof priv_data_4);
    Bytes pubPart4(pub_data_4_unc, pub_data_4_unc + sizeof pub_data_4_unc);
    Bytes bothParts4(pub_data_4_unc, pub_data_4_unc + sizeof pub_data_4_unc);
    bothParts4.insert(bothParts4.end(), privPart4.begin(), privPart4.end());
    EXPECT_EQ(sizeof priv_data_4, privPart4.size());
    EXPECT_EQ(sizeof pub_data_4_unc, pubPart4.size());
    EXPECT_EQ(65+32, bothParts4.size());

    // import and export key public part
    auto key4Pub = AsyncKeyUtils::fromRawP256("secp256k1", pubPart4);
    Bytes rawPublic4 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key4Pub, false);
    EXPECT_EQ(sizeof pub_data_4_unc, rawPublic4.size());
    EXPECT_EQ(pubPart4, rawPublic4);
    
    // import and export both key public and private parts
    auto key4Priv = AsyncKeyUtils::fromRawP256("secp256k1", bothParts4);
    Bytes rawPrivate4 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key4Priv);
    EXPECT_EQ(65+32, bothParts4.size());
    EXPECT_EQ(bothParts4, rawPrivate4);
}

TEST(AsyncKeyUtilsTest, secp256k1CalculatePublicPart4) {
    Bytes privPart4(priv_data_4, priv_data_4 + sizeof priv_data_4);
    Bytes pubPart4(pub_data_4_unc, pub_data_4_unc + sizeof pub_data_4_unc);
    Bytes bothParts4(pub_data_4_unc, pub_data_4_unc + sizeof pub_data_4_unc);
    bothParts4.insert(bothParts4.end(), privPart4.begin(), privPart4.end());
    EXPECT_EQ(sizeof priv_data_4, privPart4.size());
    EXPECT_EQ(sizeof pub_data_4_unc, pubPart4.size());
    EXPECT_EQ(65+32, bothParts4.size());

    // calculate and inject public part to private-only key
    auto key4PrivOnly = AsyncKeyUtils::fromRawP256PrivateOnly("secp256k1", privPart4);
    Bytes computedPublic4 = AsyncKeyUtils::GetPubKeyFromPrivKey(key4PrivOnly.get(), false, true);
    Bytes rawPublicInjected4 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key4PrivOnly, false);
    Bytes rawPrivateCombined4 = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key4PrivOnly, true);

    EXPECT_EQ(sizeof pub_data_4_unc, computedPublic4.size());
    EXPECT_EQ(sizeof pub_data_4_unc, rawPublicInjected4.size());
    EXPECT_EQ(65 + 32, rawPrivateCombined4.size());

    EXPECT_EQ(pubPart4, computedPublic4);
    EXPECT_EQ(pubPart4, rawPublicInjected4);
    EXPECT_EQ(bothParts4, rawPrivateCombined4);

    // calculate public part in compressed form
    Bytes pubPart4Compr(pub_data_4_compr, pub_data_4_compr + sizeof pub_data_4_compr);
    Bytes computedPublic4Compr = AsyncKeyUtils::GetPubKeyFromPrivKey(key4PrivOnly.get(), true);
    EXPECT_EQ(sizeof pub_data_4_compr, computedPublic4Compr.size());
    EXPECT_EQ(pubPart4Compr, computedPublic4Compr);
}

TEST(AsyncKeyUtilsTest, secp256k1GenerateSignVerify) {
    auto key1 = AsyncKeyUtils::getRandomKey(AsymAlg::secp256k1);
    Bytes key1pubBytes = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key1, false);
    auto key1pub = AsyncKeyUtils::fromRawP256("secp256k1", key1pubBytes);

    auto key2 = AsyncKeyUtils::getRandomKey(AsymAlg::secp256k1);
    Bytes key2pubBytes = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key2, false);
    auto key2pub = AsyncKeyUtils::fromRawP256("secp256k1", key2pubBytes);

    Bytes message = Utils::s2b("Message to sign");

    // Signing
    Bytes sign1 = AsyncKeyUtils::sign(AsymAlg::secp256k1, key1.get(), message);
    Bytes sign2 = AsyncKeyUtils::sign(AsymAlg::secp256k1, key2.get(), message);

    // Verifying - positive
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, key1.get(), message, sign1));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, key1pub.get(), message, sign1));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, key2.get(), message, sign2));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, key2pub.get(), message, sign2));

    // Verifying - negative
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, key1.get(), message, sign2));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, key1pub.get(), message, sign2));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, key2.get(), message, sign1));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, key2pub.get(), message, sign1));
}


// } // namespace ecc
} // namespace cryptoservice
} // namespace privmx
