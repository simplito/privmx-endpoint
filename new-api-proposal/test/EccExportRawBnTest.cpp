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
// #include "ECIES.hpp"


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

TEST(EccTest, ExportRawBnBasicTests) {

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

    const string expected_publ1raw("\x02\x83\xDC\x94\x5E\xBC\xA5\x55\xC3\x89\xDB\xEE\x2B\x35\x88\x13\xBD\x88\x29\x9C\xAF\xC3\x77\xC4\x36\x0C\x42\x78\x8C\xA6\x81\xC8\xB6");
    const string expected_priv1raw("\x81\x3D\xE0\x0E\xB4\x3C\x22\x7E\xAF\x82\x47\x40\xBC\xEE\x66\xF8\xB8\xE4\xC0\x83\x83\x34\x83\x65\x8C\x8C\x65\xE7\xD9\xCD\x76\xC9");
    const string expected_BNraw("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xBA\xAE\xDC\xE6\xAF\x48\xA0\x3B\xBF\xD2\x5E\x8C\xD0\x36\x41\x41");

    EXPECT_EQ(priv1.getEccKey().getPublicKey(),expected_publ1raw);
    EXPECT_EQ(priv1.getEccKey().getPrivateKey(),expected_priv1raw);

    // const string messageToSign("Sample message");

    EXPECT_EQ(priv1.getEccKey().getEcOrder().toBuffer(), expected_BNraw);
    
    EXPECT_EQ(priv1.getEccKey().getOrder2().toBuffer(), expected_BNraw);

    EXPECT_EQ(priv1.getEccKey().getOrder(), expected_BNraw);

    const string expected_derPriv1Pub2("\x11\x5F\x05\xC6\x0D\x54\xDB\x1D\xAD\x83\x07\x55\x12\x72\x3F\x34\xF9\x3B\x82\x40\xC3\x30\x58\x97\xD3\xFD\xDD\x85\xFA\x24\x5E\x34");
    const string expected_derPriv2Pub1("\x11\x5F\x05\xC6\x0D\x54\xDB\x1D\xAD\x83\x07\x55\x12\x72\x3F\x34\xF9\x3B\x82\x40\xC3\x30\x58\x97\xD3\xFD\xDD\x85\xFA\x24\x5E\x34");
    const string expected_derPriv3Pub4("\x0F\x47\xBD\xE4\x90\x06\xCC\x40\x67\x53\x32\x88\xF0\x42\x18\x42\x71\x2E\x0C\xB9\x53\xBA\xB9\x6B\x82\xCD\xF5\xE0\x93\x8D\xBC\xD1");
    const string expected_derPriv4Pub3("\x0F\x47\xBD\xE4\x90\x06\xCC\x40\x67\x53\x32\x88\xF0\x42\x18\x42\x71\x2E\x0C\xB9\x53\xBA\xB9\x6B\x82\xCD\xF5\xE0\x93\x8D\xBC\xD1");

    EXPECT_EQ(priv1.derive(publ2),expected_derPriv1Pub2);
    EXPECT_EQ(priv2.derive(publ1),expected_derPriv2Pub1);
    EXPECT_EQ(priv3.derive(publ4),expected_derPriv3Pub4);
    EXPECT_EQ(priv4.derive(publ3),expected_derPriv4Pub3);

    const string expected_ecies12_enc("\xC7\x09\x44\x6C\x13\x95\x0F\xDE\xDF\x20\x34\x02\xC9\xC9\x22\x8C\xF6\x4C\x9C\xB6\xA8\x3D\x31\xA5\x89\x87\x39\x28\xF1\x6A\x96\x3F\xBF\x8A\x2C\x1D");
    const string expected_ecies21_enc("\x3D\xE8\x21\xC2\x47\xF1\x36\xA7\x1B\x70\xF2\x9F\x89\xB7\xA9\xC6\x40\xA0\x08\xB4\x4E\x73\x13\x76\xE6\xD2\x23\x8D\xD7\x3D\x04\x86\xDB\xC1\x0D\x0A");
    const string expected_ecies34_enc("\x4C\xD5\x01\x33\xA5\x01\x1C\x61\xB2\x0A\xFD\x91\x6D\xE9\xB2\xCB\x9F\x41\x5A\xF7\xBF\x5D\x1F\x0A\x8A\x39\xB0\x44\x7D\x34\xB0\x89\x57\x5A\xB6\x56");
    const string expected_ecies43_enc("\xFD\x3C\xEE\xA0\x3A\x1E\x70\xA8\x54\x28\x51\x05\x9E\xD0\xBD\x34\x27\x09\x6D\xA2\xB8\xAB\xCF\xFD\x93\xAF\x57\xB4\xB8\x42\x8F\x84\x84\xEA\x2A\xCF");

    // ECIES ecies12(priv1, publ2);
    // ECIES ecies21(priv2, publ1);
    // ECIES ecies34(priv3, publ4);
    // ECIES ecies43(priv4, publ4);

    // // encryption tests
    // EXPECT_EQ(ecies12.encrypt(messageToSign), expected_ecies12_enc);
    // EXPECT_EQ(ecies21.encrypt(messageToSign), expected_ecies21_enc);
    // EXPECT_EQ(ecies34.encrypt(messageToSign), expected_ecies34_enc);
    // EXPECT_EQ(ecies43.encrypt(messageToSign), expected_ecies43_enc);

    // // decryption tests
    // EXPECT_EQ(ecies12.decrypt(ecies12.encrypt(messageToSign)), messageToSign);
    // EXPECT_EQ(ecies21.decrypt(ecies21.encrypt(messageToSign)), messageToSign);
    // EXPECT_EQ(ecies34.decrypt(ecies34.encrypt(messageToSign)), messageToSign);
    // EXPECT_EQ(ecies43.decrypt(ecies43.encrypt(messageToSign)), messageToSign);

    const string expected_sign1("\x1B\xDB\x7A\x57\xA6\xB4\x57\xC4\xD1\x54\xB1\x37\x60\xF1\xD4\x0C\x68\x02\xB2\xED\x0F\x0F\x55\xCE\x67\x00\x28\x3D\xBF\xC3\xFD\x1B\x40\x7C\xC8\xC4\x65\x6D\xB3\x11\xCE\xA0\xB9\x78\x68\xFB\x32\x44\x1A\x6D\x74\x1D\xAC\xF7\x6F\xA0\x3D\x7E\xA0\xE3\xEC\x5C\x0F\xDA\x4A");

    const string expected_sign1wh("\x1B\x9B\x3E\x97\x2B\xD8\x16\x79\xE0\xF3\x06\xCB\x09\xDF\x1B\xB7\xF0\x7F\x0C\x7E\x5F\xBB\xA6\x2B\x66\x1C\xC9\x27\xF2\x0E\xE7\xCE\x64\xA7\x9F\x1A\xAD\xF8\x04\x4F\x13\x9B\x8E\xC5\xD5\x1B\x65\x60\x8B\xE5\x55\x0B\xEF\x30\xBC\x63\xAD\x66\xD3\xC0\x68\xF4\x95\x6B\xE6");

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
}

} // namespace ecc
} // namespace cryptoservice
} // namespace privmx
