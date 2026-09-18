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


TEST(AsyncKeyUtilsTest, secp256k1CompactSign) {
    auto key1 = AsyncKeyUtils::getRandomKey(AsymAlg::secp256k1);
    Bytes key1pubBytes = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key1, false);
    auto key1pub = AsyncKeyUtils::fromRawP256("secp256k1", key1pubBytes);

    auto key2 = AsyncKeyUtils::getRandomKey(AsymAlg::secp256k1);
    Bytes key2pubBytes = AsyncKeyUtils::toRaw(AsymAlg::secp256k1, key2, false);
    auto key2pub = AsyncKeyUtils::fromRawP256("secp256k1", key2pubBytes);

    Bytes message = Utils::s2b("Message to sign");

    Bytes sign1 = AsyncKeyUtils::sign(AsymAlg::secp256k1, key1.get(), message);
    Bytes sign2 = AsyncKeyUtils::sign(AsymAlg::secp256k1, key2.get(), message);

    Bytes sign1a = AsyncKeyUtils::sign(AsymAlg::secp256k1, SigScheme::Default, key1.get(), message);
    Bytes sign1b = AsyncKeyUtils::sign(AsymAlg::secp256k1, SigScheme::Compact, key1.get(), message);
    Bytes sign1c = AsyncKeyUtils::sign(AsymAlg::secp256k1, SigScheme::CompactWithHash, key1.get(), message);

    Bytes sign2a = AsyncKeyUtils::sign(AsymAlg::secp256k1, SigScheme::Default, key2.get(), message);
    Bytes sign2b = AsyncKeyUtils::sign(AsymAlg::secp256k1, SigScheme::Compact, key2.get(), message);
    Bytes sign2c = AsyncKeyUtils::sign(AsymAlg::secp256k1, SigScheme::CompactWithHash, key2.get(), message);

    EXPECT_TRUE(sign1.size() >= 70);
    EXPECT_TRUE(sign1.size() <= 72);
    EXPECT_TRUE(sign1a.size() >= 70);
    EXPECT_TRUE(sign1a.size() <= 72);
    EXPECT_EQ(65, sign1b.size());
    EXPECT_EQ(65, sign1c.size());

    EXPECT_TRUE(sign2.size() >= 70);
    EXPECT_TRUE(sign2.size() <= 72);
    EXPECT_TRUE(sign2a.size() >= 70);
    EXPECT_TRUE(sign2a.size() <= 72);
    EXPECT_EQ(65, sign2b.size());
    EXPECT_EQ(65, sign2c.size());

    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, key1.get(), message, sign1));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Default, key1.get(), message, sign1a));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Compact, key1.get(), message, sign1b));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::CompactWithHash, key1.get(), message, sign1c));

    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, key1pub.get(), message, sign1));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Default, key1pub.get(), message, sign1a));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Compact, key1pub.get(), message, sign1b));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::CompactWithHash, key1pub.get(), message, sign1c));

    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Compact, key1.get(), message, sign1c));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::CompactWithHash, key1.get(), message, sign1b));

    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, key2.get(), message, sign2));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Default, key2.get(), message, sign2a));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Compact, key2.get(), message, sign2b));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::CompactWithHash, key2.get(), message, sign2c));

    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, key2pub.get(), message, sign2));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Default, key2pub.get(), message, sign2a));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Compact, key2pub.get(), message, sign2b));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::CompactWithHash, key2pub.get(), message, sign2c));

    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Compact, key2.get(), message, sign2c));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::CompactWithHash, key2.get(), message, sign2b));

    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Default, key1.get(), message, sign2));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Default, key1.get(), message, sign2a));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Default, key1pub.get(), message, sign2));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Default, key1pub.get(), message, sign2a));

    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Default, key2.get(), message, sign1));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Default, key2.get(), message, sign1a));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Default, key2pub.get(), message, sign1));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::secp256k1, SigScheme::Default, key2pub.get(), message, sign1a));
}

TEST(AsyncKeyUtilsTest, prime256v1CompactSign) {
    Bytes message = Utils::s2b("Message to sign");
    auto key3 = AsyncKeyUtils::getRandomKey(AsymAlg::prime256v1);
    Bytes sign3 = AsyncKeyUtils::sign(AsymAlg::prime256v1, key3.get(), message);
    Bytes sign3a = AsyncKeyUtils::sign(AsymAlg::prime256v1, SigScheme::Default, key3.get(), message);
    Bytes sign3b = AsyncKeyUtils::sign(AsymAlg::prime256v1, SigScheme::Compact, key3.get(), message);
    Bytes sign3c = AsyncKeyUtils::sign(AsymAlg::prime256v1, SigScheme::CompactWithHash, key3.get(), message);

    EXPECT_TRUE(sign3.size() >= 70);
    EXPECT_TRUE(sign3.size() <= 72);
    EXPECT_TRUE(sign3a.size() >= 70);
    EXPECT_TRUE(sign3a.size() <= 72);
    EXPECT_EQ(65, sign3b.size());
    EXPECT_EQ(65, sign3c.size());

    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::prime256v1, key3.get(), message, sign3));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::prime256v1, SigScheme::Default, key3.get(), message, sign3a));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::prime256v1, SigScheme::Compact, key3.get(), message, sign3b));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::prime256v1, SigScheme::CompactWithHash, key3.get(), message, sign3c));

    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::prime256v1, SigScheme::Compact, key3.get(), message, sign3c));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::prime256v1, SigScheme::CompactWithHash, key3.get(), message, sign3b));
}

TEST(AsyncKeyUtilsTest, brainpoolP256r1CompactSign) {
    Bytes message = Utils::s2b("Message to sign");
    auto key4 = AsyncKeyUtils::getRandomKey(AsymAlg::brainpoolP256r1);
    Bytes sign4 = AsyncKeyUtils::sign(AsymAlg::brainpoolP256r1, key4.get(), message);
    Bytes sign4a = AsyncKeyUtils::sign(AsymAlg::brainpoolP256r1, SigScheme::Default, key4.get(), message);
    Bytes sign4b = AsyncKeyUtils::sign(AsymAlg::brainpoolP256r1, SigScheme::Compact, key4.get(), message);
    Bytes sign4c = AsyncKeyUtils::sign(AsymAlg::brainpoolP256r1, SigScheme::CompactWithHash, key4.get(), message);

    EXPECT_TRUE(sign4.size() >= 70);
    EXPECT_TRUE(sign4.size() <= 72);
    EXPECT_TRUE(sign4a.size() >= 70);
    EXPECT_TRUE(sign4a.size() <= 72);
    EXPECT_EQ(65, sign4b.size());
    EXPECT_EQ(65, sign4c.size());

    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::brainpoolP256r1, key4.get(), message, sign4));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::brainpoolP256r1, SigScheme::Default, key4.get(), message, sign4a));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::brainpoolP256r1, SigScheme::Compact, key4.get(), message, sign4b));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::brainpoolP256r1, SigScheme::CompactWithHash, key4.get(), message, sign4c));

    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::brainpoolP256r1, SigScheme::Compact, key4.get(), message, sign4c));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::brainpoolP256r1, SigScheme::CompactWithHash, key4.get(), message, sign4b));
}

TEST(AsyncKeyUtilsTest, ED25519CompactSign) {
    Bytes message = Utils::s2b("Message to sign");
    auto key5 = AsyncKeyUtils::getRandomKey(AsymAlg::ED25519);
    Bytes sign5 = AsyncKeyUtils::sign(AsymAlg::ED25519, key5.get(), message);
    Bytes sign5a = AsyncKeyUtils::sign(AsymAlg::ED25519, SigScheme::Default, key5.get(), message);
    Bytes sign5b = AsyncKeyUtils::sign(AsymAlg::ED25519, SigScheme::Compact, key5.get(), message);
    Bytes sign5c = AsyncKeyUtils::sign(AsymAlg::ED25519, SigScheme::CompactWithHash, key5.get(), message);

    EXPECT_EQ(64, sign5.size());
    EXPECT_EQ(64, sign5a.size());
    EXPECT_EQ(65, sign5b.size());
    EXPECT_EQ(65, sign5c.size());

    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::ED25519, key5.get(), message, sign5));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::ED25519, SigScheme::Default, key5.get(), message, sign5a));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::ED25519, SigScheme::Compact, key5.get(), message, sign5b));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::ED25519, SigScheme::CompactWithHash, key5.get(), message, sign5c));

    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::ED25519, SigScheme::Compact, key5.get(), message, sign5c));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::ED25519, SigScheme::CompactWithHash, key5.get(), message, sign5b));
}

// } // namespace ecc
} // namespace cryptoservice
} // namespace privmx
