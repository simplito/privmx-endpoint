
#include <gtest/gtest.h>
#include "../utils/BaseTest.hpp"
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/Utils.hpp>
#include <privmx/crypto/Crypto.hpp>

using namespace privmx::endpoint;

class UtilsTest : public privmx::test::BaseTest {
protected:
    UtilsTest() : BaseTest(privmx::test::BaseTestMode::offline) {}
    void customSetUp() override {
        auto iniFile = std::getenv("INI_FILE_PATH");
        reader = new Poco::Util::IniFileConfiguration(iniFile);
    }
    void customTearDown() override { // tmp segfault fix
    }
    Poco::Util::IniFileConfiguration::Ptr reader;
};

TEST_F(UtilsTest, Hex) {
    core::Buffer text = core::Buffer::from("Test Hex");
    core::Buffer textInHex = core::Buffer::from("5465737420486578");
    EXPECT_EQ(textInHex, privmx::endpoint::core::Hex::encode(text));
    EXPECT_EQ(text, privmx::endpoint::core::Hex::decode(textInHex));
    EXPECT_EQ(true, privmx::endpoint::core::Hex::is(textInHex));
    core::Buffer randomText = core::Buffer::from(privmx::crypto::Crypto::randomBytes(1024));
    EXPECT_EQ(randomText, privmx::endpoint::core::Hex::decode(privmx::endpoint::core::Hex::encode(randomText)));
    EXPECT_EQ(true, privmx::endpoint::core::Hex::is(privmx::endpoint::core::Hex::encode(randomText)));
    EXPECT_EQ(false, privmx::endpoint::core::Hex::is(core::Buffer::from("blach")));
    EXPECT_EQ(true, privmx::endpoint::core::Hex::is(core::Buffer::from("1234567890ABCDE")));
    EXPECT_EQ(core::Buffer::from("\xAA\xBB"), privmx::endpoint::core::Hex::decode(core::Buffer::from("aabb")));
}

TEST_F(UtilsTest, Base32) {
    core::Buffer text = core::Buffer::from("Test Base32");
    core::Buffer textInBase32 = core::Buffer::from("KRSXG5BAIJQXGZJTGI======");
    EXPECT_EQ(textInBase32, privmx::endpoint::core::Base32::encode(text));
    EXPECT_EQ(text, privmx::endpoint::core::Base32::decode(textInBase32));
    EXPECT_EQ(true, privmx::endpoint::core::Base32::is(textInBase32));
    core::Buffer randomText = core::Buffer::from(privmx::crypto::Crypto::randomBytes(1024));
    EXPECT_EQ(randomText, privmx::endpoint::core::Base32::decode(privmx::endpoint::core::Base32::encode(randomText)));
    EXPECT_EQ(true, privmx::endpoint::core::Base32::is(privmx::endpoint::core::Base32::encode(randomText)));
    EXPECT_EQ(false, privmx::endpoint::core::Base32::is(core::Buffer::from("blach")));
}

TEST_F(UtilsTest, Base64) {
    core::Buffer text = core::Buffer::from("Test Base64");
    core::Buffer textInBase64 = core::Buffer::from("VGVzdCBCYXNlNjQ=");
    EXPECT_EQ(textInBase64, privmx::endpoint::core::Base64::encode(text));
    EXPECT_EQ(text, privmx::endpoint::core::Base64::decode(textInBase64));
    EXPECT_EQ(true, privmx::endpoint::core::Base64::is(textInBase64));
    core::Buffer randomText = core::Buffer::from(privmx::crypto::Crypto::randomBytes(1024));
    EXPECT_EQ(randomText, privmx::endpoint::core::Base64::decode(privmx::endpoint::core::Base64::encode(randomText)));
    EXPECT_EQ(true, privmx::endpoint::core::Base64::is(privmx::endpoint::core::Base64::encode(randomText)));
    EXPECT_EQ(false, privmx::endpoint::core::Base64::is(core::Buffer::from("blach")));
}

TEST_F(UtilsTest, Utils) {
    EXPECT_EQ(32, privmx::endpoint::core::Utils::fillTo32("test").length());
    EXPECT_EQ("test/", privmx::endpoint::core::Utils::removeEscape("test\\/"));
    EXPECT_EQ("TESTB", privmx::endpoint::core::Utils::formatToBase32("test b"));
    EXPECT_EQ("test", privmx::endpoint::core::Utils::trim(" test "));
    EXPECT_EQ(std::vector<std::string>({"test","test"}), privmx::endpoint::core::Utils::split("test, test", ", "));
    EXPECT_EQ(std::vector<std::string>({"test","test"}), privmx::endpoint::core::Utils::splitStringByCharacter("test- test", '-'));
    std::string test = " test ";
    privmx::endpoint::core::Utils::ltrim(test);
    EXPECT_EQ("test ", test);
    privmx::endpoint::core::Utils::rtrim(test);
    EXPECT_EQ("test", test);
}