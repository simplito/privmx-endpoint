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


TEST(AsyncKeyUtilsTest, ED25519GenerateSignVerify) {
    auto key1 = AsyncKeyUtils::getRandomKey(AsymAlg::ED25519);
    Bytes key1pubBytes = AsyncKeyUtils::toRaw(AsymAlg::ED25519, key1, false);
    auto key1pub = AsyncKeyUtils::fromRaw25519("ED25519", key1pubBytes);

    auto key2 = AsyncKeyUtils::getRandomKey(AsymAlg::ED25519);
    Bytes key2pubBytes = AsyncKeyUtils::toRaw(AsymAlg::ED25519, key2, false);
    auto key2pub = AsyncKeyUtils::fromRaw25519("ED25519", key2pubBytes);

    Bytes message = Utils::s2b("Message to sign");

    // Signing
    Bytes sign1 = AsyncKeyUtils::sign(AsymAlg::ED25519, key1.get(), message);
    Bytes sign2 = AsyncKeyUtils::sign(AsymAlg::ED25519, key2.get(), message);

    // Verifying - positive
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::ED25519, key1.get(), message, sign1));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::ED25519, key1pub.get(), message, sign1));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::ED25519, key2.get(), message, sign2));
    EXPECT_TRUE(AsyncKeyUtils::verify(AsymAlg::ED25519, key2pub.get(), message, sign2));

    // Verifying - negative
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::ED25519, key1.get(), message, sign2));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::ED25519, key1pub.get(), message, sign2));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::ED25519, key2.get(), message, sign1));
    EXPECT_FALSE(AsyncKeyUtils::verify(AsymAlg::ED25519, key2pub.get(), message, sign1));

}

// } // namespace ecc
} // namespace cryptoservice
} // namespace privmx
