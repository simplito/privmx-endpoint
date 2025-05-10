
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
    // Consts
    // Keys
    std::string _PGPkey =
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
    "xk8EZ/jEchMFK4EEAAoCAwSEyo++5XMwfoPCwDUOEIsHtjS9uG1oSb+9cR0/nyJZ\n"
    "cwm8oTdBqHcksITfIiKdyhGLPP3MvGGlpu4uevoM7cVZ\n"
    "=LRYU\n"
    "-----END PGP PUBLIC KEY BLOCK-----\n";
    // BIP39
    const std::string _BIP39_mnemonic = "segment machine okay tank speak giraffe exercise mixed awkward welcome carry wisdom";
    const std::string _BIP39_entropy = privmx::utils::Hex::toString("c330b267eedd0cc453d47110df288bfe");
    const std::string _BIP39_password = "password";
    const std::string _BIP39_privatePartAsBase58_withoutPassword = "xprv9s21ZrQH143K2S9osSQbnVRZY3fgyJ36oxS35mPEPEkoaEXGRegy8HFavePnVqM6eUd9agxwJyrDmYoJ7BJtbwZrc5S63chmH5rD4rwejUA";
    const std::string _BIP39_privatePartAsBase58_withPassword = "xprv9s21ZrQH143K3nFYh4axNfWq5k4xn8qspfzzZRS8u6D2awiBfe6Tc8Je3NjhXfz1YbjKCTMqPJUdBieU4k9sbZogccWe4PKHEWdxaVzyZE3";
    const std::string _BIP39_publicPartAsBase58_withoutPassword = "xpub661MyMwAqRbcEvEGyTwc9dNJ65WBNkkxBBMdt9nqwaHnT2rQyC1Dg5a4mw6gJ1QUBBDq7YguV26kHuJgLNVBL3wBwLzhgUPQ85Er6Tn5Eq2";
    const std::string _BIP39_publicPartAsBase58_withPassword = "xpub661MyMwAqRbcGGL1o67xjoTZdmuTBbZjBtvbMoqkTRk1Tk3LDBQi9vd7tdKFss79vRWUaX14biVwRDSYzJW4YkmH4LvkGq6zfsSctGxoidd";
    const std::string _BIP39_seed_withoutPassword = privmx::utils::Hex::toString(
        "69aee18924f7e6724a7598d49813cfa4eadd31b7671367c7f6de784479d75e1aa4904a498b75e9bcde322bd1011d205d3051ba43c3b4c3a3296451b1a36044f7"
    );
    const std::string _BIP39_seed_withPassword = privmx::utils::Hex::toString(
        "b4d611c2a1cc7b8fccfb14623fb800bde4764388ff766673dccf54cc4b65d35cbc0ff296dde8b3246075458d75f7c4bc3e2c4242c2d4e1c2268e942f040ae943"
    );
    const std::string _BIP39_publicKeyBase58DER_withPassword = "67r77s6cs14ErtuLqCv4cgsHUm7dQTvGKx3Mb5DxSXCAUuPygY";
    const std::string _BIP39_publicKeyBase58DERAddress_withPassword = "1NbGbcmEVw8nUsRmfeN6m1GQtJX62BwRyS";
    const std::string _BIP39_privateKeyWIF_withPassword = "L4eMAP7f7PSGCY8fNVMv66JDczN6wDnGv4ZL2nwf4kTZxvmtp8D6";
    const std::string _BIP39_chainCode_withPassword = privmx::utils::Hex::toString(
        "acfe0e248220d8879beb8c2ba570098b118a5e3b20912cbcdb073422ca96fbd3"
    );
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

TEST_F(CryptoTest, convertPGPAsn1KeyToBase58DERKey) {
    std::string keyInBase58DER;
    EXPECT_NO_THROW({
        keyInBase58DER = cryptoApi->convertPGPAsn1KeyToBase58DERKey(_PGPkey);
    });
    EXPECT_NO_THROW({
        privmx::crypto::PublicKey::fromBase58DER(keyInBase58DER);
    });
    EXPECT_EQ(keyInBase58DER, "7qiWDFa1gEEiEowrBxrGNfKNV9oLtpYGTnZeQ7Y82CdJ7qBTPe");
}

TEST_F(CryptoTest, generateBip39) {
    EXPECT_NO_THROW({
        cryptoApi->generateBip39(128, _BIP39_password);
    });;
}

TEST_F(CryptoTest, fromMnemonic) {
    privmx::endpoint::crypto::BIP39_t bip39;
    EXPECT_NO_THROW({
        bip39 = cryptoApi->fromMnemonic(_BIP39_mnemonic);
    });
    EXPECT_EQ(bip39.mnemonic, _BIP39_mnemonic);
    EXPECT_EQ(bip39.entropy.stdString(), _BIP39_entropy);
    EXPECT_EQ(bip39.ext_key.getPrivatePartAsBase58(), _BIP39_privatePartAsBase58_withoutPassword);

    EXPECT_NO_THROW({
        bip39 = cryptoApi->fromMnemonic(_BIP39_mnemonic, _BIP39_password);
    });
    EXPECT_EQ(bip39.mnemonic, _BIP39_mnemonic);
    EXPECT_EQ(bip39.entropy.stdString(), _BIP39_entropy);
    EXPECT_EQ(bip39.ext_key.getPrivatePartAsBase58(), _BIP39_privatePartAsBase58_withPassword);
}

TEST_F(CryptoTest, fromEntropy) {
    privmx::endpoint::crypto::BIP39_t bip39;
    EXPECT_NO_THROW({
        bip39 = cryptoApi->fromEntropy(core::Buffer::from(_BIP39_entropy));
    });
    EXPECT_EQ(bip39.mnemonic, _BIP39_mnemonic);
    EXPECT_EQ(bip39.entropy.stdString(), _BIP39_entropy);
    EXPECT_EQ(bip39.ext_key.getPrivatePartAsBase58(), _BIP39_privatePartAsBase58_withoutPassword);

    EXPECT_NO_THROW({
        bip39 = cryptoApi->fromEntropy(core::Buffer::from(_BIP39_entropy), _BIP39_password);
    });
    EXPECT_EQ(bip39.mnemonic, _BIP39_mnemonic);
    EXPECT_EQ(bip39.entropy.stdString(), _BIP39_entropy);
    EXPECT_EQ(bip39.ext_key.getPrivatePartAsBase58(), _BIP39_privatePartAsBase58_withPassword);
}

TEST_F(CryptoTest, entropyToMnemonic) {
    std::string resultMnemonic;
    EXPECT_NO_THROW({
        resultMnemonic = cryptoApi->entropyToMnemonic(core::Buffer::from(_BIP39_entropy));
    });
    EXPECT_EQ(resultMnemonic, _BIP39_mnemonic);
}

TEST_F(CryptoTest, mnemonicToEntropy) {
    std::string resultEntropy;
    EXPECT_NO_THROW({
        resultEntropy = cryptoApi->mnemonicToEntropy(_BIP39_mnemonic).stdString();
    });
    EXPECT_EQ(resultEntropy, _BIP39_entropy);
}

TEST_F(CryptoTest, mnemonicToSeed) {
    std::string resultSeed;
    EXPECT_NO_THROW({
        resultSeed = cryptoApi->mnemonicToSeed(_BIP39_mnemonic).stdString();
    });
    EXPECT_EQ(resultSeed, _BIP39_seed_withoutPassword);
    EXPECT_NO_THROW({
        resultSeed = cryptoApi->mnemonicToSeed(_BIP39_mnemonic, _BIP39_password).stdString();
    });
    EXPECT_EQ(resultSeed, _BIP39_seed_withPassword);
}

TEST_F(CryptoTest, ExtKey_fromSeed) {
    privmx::endpoint::crypto::ExtKey ext_key;
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromSeed(core::Buffer::from(_BIP39_seed_withoutPassword));
    });
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromSeed(core::Buffer::from(_BIP39_seed_withPassword));
    });
}

TEST_F(CryptoTest, ExtKey_fromBase58) {
    privmx::endpoint::crypto::ExtKey ext_key;
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromBase58(_BIP39_privatePartAsBase58_withoutPassword);
    });
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromBase58(_BIP39_privatePartAsBase58_withPassword);
    });
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromBase58(_BIP39_publicPartAsBase58_withoutPassword);
    });
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromBase58(_BIP39_publicPartAsBase58_withPassword);
    });
}

TEST_F(CryptoTest, ExtKey_derive_deriveHardened) {
    privmx::endpoint::crypto::ExtKey ext_key;
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromSeed(core::Buffer::from(_BIP39_seed_withPassword));
    });
    EXPECT_NO_THROW({
        privmx::endpoint::crypto::ExtKey derivedKey1 = ext_key.derive(8);
        privmx::endpoint::crypto::ExtKey derivedKey2 = ext_key.derive(8);
        EXPECT_EQ(derivedKey1.getPublicPartAsBase58(), derivedKey2.getPublicPartAsBase58());
        EXPECT_EQ(derivedKey1.getPrivatePartAsBase58(), derivedKey2.getPrivatePartAsBase58());
    });
    EXPECT_NO_THROW({
        privmx::endpoint::crypto::ExtKey derivedKey1 = ext_key.deriveHardened(8);
        privmx::endpoint::crypto::ExtKey derivedKey2 = ext_key.deriveHardened(8);
        EXPECT_EQ(derivedKey1.getPublicPartAsBase58(), derivedKey2.getPublicPartAsBase58());
        EXPECT_EQ(derivedKey1.getPrivatePartAsBase58(), derivedKey2.getPrivatePartAsBase58());
    });
    EXPECT_NO_THROW({
        privmx::endpoint::crypto::ExtKey derivedKey1 = ext_key.derive(8);
        privmx::endpoint::crypto::ExtKey derivedKey2 = ext_key.deriveHardened(8);
        EXPECT_TRUE(derivedKey1.getPublicPartAsBase58() != derivedKey2.getPublicPartAsBase58());
        EXPECT_TRUE(derivedKey1.getPrivatePartAsBase58() != derivedKey2.getPrivatePartAsBase58());
    });
}

TEST_F(CryptoTest, ExtKey_getPrivatePartAsBase58) {
    privmx::endpoint::crypto::ExtKey ext_key;
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromSeed(core::Buffer::from(_BIP39_seed_withPassword));
    });
    std::string privatePart;
    EXPECT_NO_THROW({
        privatePart = ext_key.getPrivatePartAsBase58();
    });
    EXPECT_EQ(privatePart, _BIP39_privatePartAsBase58_withPassword);
}

TEST_F(CryptoTest, ExtKey_getPublicPartAsBase58) {
    privmx::endpoint::crypto::ExtKey ext_key;
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromSeed(core::Buffer::from(_BIP39_seed_withPassword));
    });
    std::string publicPart;
    EXPECT_NO_THROW({
        publicPart = ext_key.getPublicPartAsBase58();
    });
    EXPECT_EQ(publicPart, _BIP39_publicPartAsBase58_withPassword);
}

TEST_F(CryptoTest, ExtKey_getPrivateKey) {
    privmx::endpoint::crypto::ExtKey ext_key;
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromSeed(core::Buffer::from(_BIP39_seed_withPassword));
    });
    std::string privateKey;
    EXPECT_NO_THROW({
        privateKey = ext_key.getPrivateKey();
    });
    EXPECT_EQ(privateKey, _BIP39_privateKeyWIF_withPassword);
}

TEST_F(CryptoTest, ExtKey_getPublicKey) {
    privmx::endpoint::crypto::ExtKey ext_key;
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromSeed(core::Buffer::from(_BIP39_seed_withPassword));
    });
    std::string publicKey;
    EXPECT_NO_THROW({
        publicKey = ext_key.getPublicKey();
    });
    EXPECT_EQ(publicKey,_BIP39_publicKeyBase58DER_withPassword);
}

TEST_F(CryptoTest, ExtKey_getPrivateEncKey) {
    privmx::endpoint::crypto::ExtKey ext_key;
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromSeed(core::Buffer::from(_BIP39_seed_withPassword));
    });
    core::Buffer privateEncKey;
    EXPECT_NO_THROW({
        privateEncKey = ext_key.getPrivateEncKey();
    });
    privmx::crypto::PrivateKey key = privmx::crypto::PrivateKey::fromWIF(_BIP39_privateKeyWIF_withPassword);
    EXPECT_EQ(privateEncKey.stdString(),key.getPrivateEncKey());
}

TEST_F(CryptoTest, ExtKey_getPublicKeyAsBase58Address) {
    privmx::endpoint::crypto::ExtKey ext_key;
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromSeed(core::Buffer::from(_BIP39_seed_withPassword));
    });
    std::string publicKeyAsBase58Address;
    EXPECT_NO_THROW({
        publicKeyAsBase58Address = ext_key.getPublicKeyAsBase58Address();
    });
    
    EXPECT_EQ(publicKeyAsBase58Address, _BIP39_publicKeyBase58DERAddress_withPassword);
}

TEST_F(CryptoTest, ExtKey_getChainCode) {
    privmx::endpoint::crypto::ExtKey ext_key;
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromSeed(core::Buffer::from(_BIP39_seed_withPassword));
    });
    core::Buffer chain_code;
    EXPECT_NO_THROW({
        chain_code = ext_key.getChainCode();
    });
    EXPECT_EQ(chain_code.stdString(),_BIP39_chainCode_withPassword);
}

TEST_F(CryptoTest, ExtKey_verifyCompactSignatureWithHash) {
    privmx::endpoint::crypto::ExtKey ext_key;
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromSeed(core::Buffer::from(_BIP39_seed_withPassword));
    });
    auto privateKey = privmx::crypto::PrivateKey::fromWIF(ext_key.getPrivateKey());
    auto sign = privateKey.signToCompactSignatureWithHash("test");
    EXPECT_TRUE(ext_key.verifyCompactSignatureWithHash(core::Buffer::from("test"), core::Buffer::from(sign)));
}

TEST_F(CryptoTest, ExtKey_isPrivate) {
    privmx::endpoint::crypto::ExtKey ext_key;
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromBase58(_BIP39_privatePartAsBase58_withoutPassword);
    });
    EXPECT_TRUE(ext_key.isPrivate());
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromBase58(_BIP39_publicPartAsBase58_withoutPassword);
    });
    EXPECT_FALSE(ext_key.isPrivate());
}