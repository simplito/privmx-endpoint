
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <privmx/endpoint/core/Utils.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/BinaryBufferBE.hpp>

using namespace privmx::endpoint;

class UtilsTest : public testing::Test {};

TEST_F(UtilsTest, Hex) {
    core::Buffer text = core::Buffer::from("Test Hex");
    std::string textInHex = "5465737420486578";
    EXPECT_EQ(textInHex, privmx::endpoint::core::Hex::encode(text));
    EXPECT_EQ(text, privmx::endpoint::core::Hex::decode(textInHex));
    EXPECT_EQ(true, privmx::endpoint::core::Hex::is(textInHex));
    core::Buffer randomText = core::Buffer::from(privmx::crypto::Crypto::randomBytes(1024));
    EXPECT_EQ(randomText, privmx::endpoint::core::Hex::decode(privmx::endpoint::core::Hex::encode(randomText)));
    EXPECT_EQ(true, privmx::endpoint::core::Hex::is(privmx::endpoint::core::Hex::encode(randomText)));
    EXPECT_EQ(false, privmx::endpoint::core::Hex::is("blach"));
    EXPECT_EQ(true, privmx::endpoint::core::Hex::is("1234567890ABCDE"));
    EXPECT_EQ(core::Buffer::from("\xAA\xBB"), privmx::endpoint::core::Hex::decode("aabb"));
}

TEST_F(UtilsTest, Base32) {
    core::Buffer text = core::Buffer::from("Test Base32");
    std::string textInBase32 = "KRSXG5BAIJQXGZJTGI======";
    EXPECT_EQ(textInBase32, privmx::endpoint::core::Base32::encode(text));
    EXPECT_EQ(text, privmx::endpoint::core::Base32::decode(textInBase32));
    EXPECT_EQ(true, privmx::endpoint::core::Base32::is(textInBase32));
    core::Buffer randomText = core::Buffer::from(privmx::crypto::Crypto::randomBytes(1024));
    EXPECT_EQ(randomText, privmx::endpoint::core::Base32::decode(privmx::endpoint::core::Base32::encode(randomText)));
    EXPECT_EQ(true, privmx::endpoint::core::Base32::is(privmx::endpoint::core::Base32::encode(randomText)));
    EXPECT_EQ(false, privmx::endpoint::core::Base32::is("blach"));
}

TEST_F(UtilsTest, Base64) {
    core::Buffer text = core::Buffer::from("Test Base64");
    std::string textInBase64 = "VGVzdCBCYXNlNjQ=";
    EXPECT_EQ(textInBase64, privmx::endpoint::core::Base64::encode(text));
    EXPECT_EQ(text, privmx::endpoint::core::Base64::decode(textInBase64));
    EXPECT_EQ(true, privmx::endpoint::core::Base64::is(textInBase64));
    core::Buffer randomText = core::Buffer::from(privmx::crypto::Crypto::randomBytes(1024));
    EXPECT_EQ(randomText, privmx::endpoint::core::Base64::decode(privmx::endpoint::core::Base64::encode(randomText)));
    EXPECT_EQ(true, privmx::endpoint::core::Base64::is(privmx::endpoint::core::Base64::encode(randomText)));
    EXPECT_EQ(false, privmx::endpoint::core::Base64::is("blach"));
}

TEST_F(UtilsTest, Utils) {
    EXPECT_EQ("test", privmx::endpoint::core::Utils::trim(" test "));
    EXPECT_EQ(std::vector<std::string>({"test","test"}), privmx::endpoint::core::Utils::split("test, test", ", "));
    std::string test = " test ";
    privmx::endpoint::core::Utils::ltrim(test);
    EXPECT_EQ("test ", test);
    privmx::endpoint::core::Utils::rtrim(test);
    EXPECT_EQ("test", test);
}
/**
 * `BinaryBufferBE`'s one-octet-length framing, on buffers it did not produce.
 *
 * Both directions used to fail silently on the two inputs below: a read past the end left the length octet
 * uninitialized and short-read the payload without complaint, and a write of 256 bytes truncated the length
 * to zero. Either one turns a malformed buffer into a well-formed buffer holding something else.
 */
TEST_F(UtilsTest, BinaryBufferBEOneOctetFramingRejectsMalformed) {
    std::string value;

    // Nothing at all: not even the length octet is there to read.
    privmx::utils::BinaryBufferBE empty(std::string{});
    EXPECT_THROW(empty.readOneOctetLengthBuffer(value), privmx::utils::BinaryBufferTruncatedException);

    // A length octet promising 255 bytes, followed by one.
    privmx::utils::BinaryBufferBE truncated(std::string("\xFF""a", 2));
    EXPECT_THROW(truncated.readOneOctetLengthBuffer(value), privmx::utils::BinaryBufferTruncatedException);

    // 256 bytes cannot be described by one octet; writing 0 instead would parse as an empty field.
    privmx::utils::BinaryBufferBE tooLong;
    EXPECT_THROW(
        tooLong.writeOneOctetLengthBuffer(std::string(256, 'a')),
        privmx::utils::BinaryBufferFieldTooLongException
    );

    // The round trip it is actually for still works, including a maximal field.
    privmx::utils::BinaryBufferBE writer;
    writer.writeOneOctetLengthBuffer(std::string(255, 'z'));
    privmx::utils::BinaryBufferBE reader(writer.str());
    reader.readOneOctetLengthBuffer(value);
    EXPECT_EQ(value, std::string(255, 'z'));
}
