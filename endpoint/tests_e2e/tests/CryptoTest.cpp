
#include <gtest/gtest.h>
#include "../utils/BaseTest.hpp"
#include <privmx/endpoint/crypto/CryptoApi.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>

using namespace privmx::endpoint;

class CryptoTest : public privmx::test::BaseTest {
protected:
    CryptoTest() : BaseTest(privmx::test::BaseTestMode::offline) {}
    void customSetUp() override {
        auto iniFile = std::getenv("INI_FILE_PATH");
        reader = new Poco::Util::IniFileConfiguration(iniFile);
        cryptoApi = std::make_shared<crypto::CryptoApi>(
            crypto::CryptoApi::create()
        );
    }
    void customTearDown() override { // tmp segfault fix
        cryptoApi.reset();
    }
    std::shared_ptr<crypto::CryptoApi> cryptoApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(CryptoTest, verifySignature) {
    core::Buffer sign = core::Buffer::from(privmx::utils::Hex::toString("1bf40aa304605ed8f94f3dc03564332f341a7620f419839c762151c50342366377207cf547e1c3837e796dd1b29e13d0772b3b9d0d53315b28fba7a4ed385d1fc4"));
    EXPECT_THROW({
        cryptoApi->verifySignature(core::Buffer::from("data"), core::Buffer::from("sign"), "8Qsc1FF9xQp3ziWLEVpAoAp4RcpBpiQ4E9oBbuKfwdqRC5KpHq");
    }, core::Exception);
    EXPECT_THROW({
        cryptoApi->verifySignature(core::Buffer::from("data"), sign, "8Qsc1FF9xQp3ziWLEVpAoAp4RcpBpiQ4E9oBbuKfwdqRC5KpHH");
    }, core::Exception);
    bool status;
    EXPECT_NO_THROW({
       status = cryptoApi->verifySignature(core::Buffer::from("data"), sign, "8Qsc1FF9xQp3ziWLEVpAoAp4RcpBpiQ4E9oBbuKfwdqRC5KpHq");
    });
    EXPECT_EQ(status, true);
}

TEST_F(CryptoTest, verifySignature2) {
    auto dataToSign {core::Buffer::from("data")};
    auto temperedData {core::Buffer::from("datax")};

    auto privKey {cryptoApi->generatePrivateKey(std::nullopt)};
    auto pubKey {cryptoApi->derivePublicKey(privKey)};
    auto signature {cryptoApi->signData(dataToSign, privKey)};

    auto verified {cryptoApi->verifySignature(dataToSign, signature, pubKey)};
    auto verified2 {cryptoApi->verifySignature(temperedData, signature, pubKey)};

    EXPECT_EQ(verified, true);
    EXPECT_EQ(verified2, false);    
}

TEST_F(CryptoTest, signData) {
    EXPECT_THROW({
        cryptoApi->signData(core::Buffer::from("data"), "8Qsc1FF9xQp3ziWLEVpAoAp4RcpBpiQ4E9oBbuKfwdqRC5KpHq");
    }, core::Exception);
    core::Buffer sign;
    EXPECT_NO_THROW({
        sign = cryptoApi->signData(core::Buffer::from("data"), "L2TUveYrXgohLcLVcvrYd48Nwy25cZNGEuGYjxwWnai2uW9KNpPb");
    });
    bool status;
    EXPECT_NO_THROW({
       status = cryptoApi->verifySignature(core::Buffer::from("data"), sign, "8Qsc1FF9xQp3ziWLEVpAoAp4RcpBpiQ4E9oBbuKfwdqRC5KpHq");
    });
    EXPECT_EQ(status, true);
} 

TEST_F(CryptoTest, generatePrivateKey) {
    std::string keyInWIF;
    EXPECT_NO_THROW({
        keyInWIF = cryptoApi->generatePrivateKey(std::nullopt);
    });
    EXPECT_NO_THROW({
        privmx::crypto::PrivateKey::fromWIF(keyInWIF);
    });
}

TEST_F(CryptoTest, derivePrivateKey) {
    std::string keyInWIF;
    EXPECT_NO_THROW({
        keyInWIF = cryptoApi->derivePrivateKey("pass","salt");
    });
    EXPECT_NO_THROW({
        privmx::crypto::PrivateKey::fromWIF(keyInWIF);
    });
    EXPECT_EQ(keyInWIF, "L2TUveYrXgohLcLVcvrYd48Nwy25cZNGEuGYjxwWnai2uW9KNpPb");
}

TEST_F(CryptoTest, derivePrivateKey2) {
    std::string keyInWIF;
    EXPECT_NO_THROW({
        keyInWIF = cryptoApi->derivePrivateKey2("pass","salt");
    });
    EXPECT_NO_THROW({
        privmx::crypto::PrivateKey::fromWIF(keyInWIF);
    });
    EXPECT_EQ(keyInWIF, "L1PtGzD2iLGT3vPQkDGqKhrYCxjBQzfnVzG1D4cTuGnPvPqZEtTP");
}

TEST_F(CryptoTest, derivePublicKey) {
    EXPECT_THROW({
        cryptoApi->derivePublicKey("8Qsc1FF9xQp3ziWLEVpAoAp4RcpBpiQ4E9oBbuKfwdqRC5KpHq");
    }, core::Exception);
    std::string keyInBase58DER;
    EXPECT_NO_THROW({
        keyInBase58DER = cryptoApi->derivePublicKey("L2TUveYrXgohLcLVcvrYd48Nwy25cZNGEuGYjxwWnai2uW9KNpPb");
    });
    EXPECT_NO_THROW({
        privmx::crypto::PublicKey::fromBase58DER(keyInBase58DER);
    });
    EXPECT_EQ(keyInBase58DER, "8Qsc1FF9xQp3ziWLEVpAoAp4RcpBpiQ4E9oBbuKfwdqRC5KpHq");
}

TEST_F(CryptoTest, generateKeySymmetric) {
    EXPECT_NO_THROW({
        cryptoApi->generateKeySymmetric();
    });
}

TEST_F(CryptoTest, encryptDataSymmetric_decryptDataSymmetric) {
    core::Buffer key = core::Buffer::from(privmx::utils::Hex::toString(
        "3ad696c8c37f286adbbd66b2f31e90041850ae2d3ec30250020c0209085f8c62"
    ));
    core::Buffer encryptedData;
    EXPECT_NO_THROW({
        encryptedData = cryptoApi->encryptDataSymmetric(core::Buffer::from("data"), key);
    });
    core::Buffer decryptedData;
    EXPECT_NO_THROW({
        decryptedData = cryptoApi->decryptDataSymmetric(encryptedData, key);
    });
    EXPECT_EQ(decryptedData.stdString(), "data");
}


TEST_F(CryptoTest, convertPEMKeytoWIFKey) {
    std::string PEMkey;
    PEMkey += "-----BEGIN EC PRIVATE KEY-----\n";
    PEMkey += "MHcCAQEEIDn+OxAnJ2hpn6DvIKPd7pZP7+icpLeob5rgkfqhhvvgoAoGCCqGSM49\n";
    PEMkey += "AwEHoUQDQgAEpjMTeBBo5FaUueJ2xdkVNDaxYYnl3PGkUMvlel20gGLuQJ8PubAd\n";
    PEMkey += "UEgv4yQFIxwLTNp7QlYqdaQTRbGjAblu9g==\n";
    PEMkey += "-----END EC PRIVATE KEY-----\n";
    std::string keyInWIF;
    EXPECT_NO_THROW({
        keyInWIF = cryptoApi->convertPEMKeytoWIFKey(PEMkey);
    });
    EXPECT_NO_THROW({
        privmx::crypto::PrivateKey::fromWIF(keyInWIF);
    });
    EXPECT_EQ(keyInWIF, "KyASahKYZjCyKJBB7ixVQbrQ7o56Vxo2PJgCuTL3YLFGBqxfPFAC");
}
