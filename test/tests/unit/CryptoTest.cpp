
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <privmx/endpoint/crypto/CryptoApi.hpp>
#include <privmx/endpoint/crypto/ExtKey.hpp>
#include <privmx/endpoint/core/crypto/KeyFormats.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx::endpoint;

class CryptoTest : public testing::Test {
protected:
    /**
     * For the cases whose expected values are secp256k1 vectors.
     *
     * `CryptoApi` follows the build's identity algorithm, so under `PRIVMX_defaultKeyAlgorithm()=ed25519`
     * these calls correctly return a different key — a fixed vector cannot describe both. The tests
     * that pin a vector say so by skipping rather than by quietly asserting the wrong build's answer.
     */
    static bool isSecp256k1Build() {
        return privmx::endpoint::core::defaultKeyAlgorithm() == privmx::cryptoservice::AsymAlg::PrivmxSecp256k1;
    }

    void SetUp() override {
        cryptoApi = std::make_shared<crypto::CryptoApi>(
            crypto::CryptoApi::create()
        );
    }
    void TearDown() override { // tmp segfault fix
        cryptoApi.reset();
    }
    std::shared_ptr<crypto::CryptoApi> cryptoApi;
    // Keys
    std::string _PGPkey =
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
    "xk8EZ/jEchMFK4EEAAoCAwSEyo++5XMwfoPCwDUOEIsHtjS9uG1oSb+9cR0/nyJZ\n"
    "cwm8oTdBqHcksITfIiKdyhGLPP3MvGGlpu4uevoM7cVZ\n"
    "=LRYU\n"
    "-----END PGP PUBLIC KEY BLOCK-----\n";
    // Seed material, named after the BIP-39 vector it came from. BIP-39 itself is gone - it cannot
    // express a post-quantum identity - but the seeds it produced are still useful fixed inputs to
    // the extended-key cases below, which is all they are used for now.
    // Not `xprv…`/`xpub…` any more: extended keys serialise in pmx-crypto's envelope, which records
    // the algorithms and can hold a composed identity. BIP-32's own format has one key slot and no
    // algorithm field, so it cannot express that. The derivation is unchanged and still pinned
    // against the specification's numbers - see ExtKeyBip32VectorsTest.
    const std::string _ExtKey_privatePartAsBase58_withPassword =
        "11157uBnWSDsKThuemijkbHRDg6b33U7mmePe7breLbiWU6xEWTaynVobtB6kYd9ygTiE8hDJw8vBbZc7g8cLmVeUHFm2rTwvm4JyhPLhhBeGpbYiWWj8XiyZ7FK";
    const std::string _ExtKey_publicPartAsBase58_withPassword =
        "11124CcKRXpzuMZCJbC7nrHrqmaXQyT25eNdR6hdVUWErPX7NUyX83Yeu1EtFKb1taetJScyUPRsUYjJNX";
    const std::string _BIP39_seed_withoutPassword = privmx::utils::Hex::toString(
        "69aee18924f7e6724a7598d49813cfa4eadd31b7671367c7f6de784479d75e1aa4904a498b75e9bcde322bd1011d205d3051ba43c3b4c3a3296451b1a36044f7"
    );
    const std::string _BIP39_seed_withPassword = privmx::utils::Hex::toString(
        "b4d611c2a1cc7b8fccfb14623fb800bde4764388ff766673dccf54cc4b65d35cbc0ff296dde8b3246075458d75f7c4bc3e2c4242c2d4e1c2268e942f040ae943"
    );
    // Untagged on purpose: `ExtKey` still goes through the legacy `crypto` module, whose base58 export
    // carries no algorithm tag. BIP32/ExtKey is a separate migration, and when it lands this value
    // becomes the tagged one — the same bytes behind an 0x81 tag.
    const std::string _BIP39_publicKeyBase58DER_withPassword_untaggedExtKey =
        "67r77s6cs14ErtuLqCv4cgsHUm7dQTvGKx3Mb5DxSXCAUuPygY";
    const std::string _BIP39_publicKeyBase58DERAddress_withPassword = "1NbGbcmEVw8nUsRmfeN6m1GQtJX62BwRyS";
    const std::string _BIP39_privateKeyWIF_withPassword = "L4eMAP7f7PSGCY8fNVMv66JDczN6wDnGv4ZL2nwf4kTZxvmtp8D6";
    const std::string _BIP39_chainCode_withPassword = privmx::utils::Hex::toString(
        "acfe0e248220d8879beb8c2ba570098b118a5e3b20912cbcdb073422ca96fbd3"
    );
};

TEST_F(CryptoTest, verifySignature) {
    core::Buffer sign = core::Buffer::from(privmx::utils::Hex::toString("1bf40aa304605ed8f94f3dc03564332f341a7620f419839c762151c50342366377207cf547e1c3837e796dd1b29e13d0772b3b9d0d53315b28fba7a4ed385d1fc4"));
    EXPECT_THROW({
        cryptoApi->verifySignature(core::Buffer::from("data"), core::Buffer::from("sign"), "L5vkdRVHpz99Wohor79hWczzv7LmWAoVQ3axynJ7fQATA7szwGWe");
    }, core::Exception);
    EXPECT_THROW({
        cryptoApi->verifySignature(core::Buffer::from("data"), sign, "L5vkdRVHpz99Wohor79hWczzv7LmWAoVQ3axynJ7fQATA7szwGWf");
    }, core::Exception);
    // The same key in the encoding used before the 3.0.0 cut. A key has to carry its algorithm, so an
    // untagged one is refused rather than read as secp256k1 by assumption.
    EXPECT_THROW({
        cryptoApi->verifySignature(core::Buffer::from("data"), sign, "8Qsc1FF9xQp3ziWLEVpAoAp4RcpBpiQ4E9oBbuKfwdqRC5KpHq");
    }, core::Exception);
    bool status;
    EXPECT_NO_THROW({
       status = cryptoApi->verifySignature(core::Buffer::from("data"), sign, "L5vkdRVHpz99Wohor79hWczzv7LmWAoVQ3axynJ7fQATA7szwGWe");
    });
    EXPECT_EQ(status, true);
}

TEST_F(CryptoTest, signData) {
    if (!isSecp256k1Build()) GTEST_SKIP() << "fixed secp256k1 vector; this build generates other keys";
    EXPECT_THROW({
        cryptoApi->signData(core::Buffer::from("data"), "L5vkdRVHpz99Wohor79hWczzv7LmWAoVQ3axynJ7fQATA7szwGWe");
    }, core::Exception);
    core::Buffer sign;
    EXPECT_NO_THROW({
        sign = cryptoApi->signData(core::Buffer::from("data"), "L2TUveYrXgohLcLVcvrYd48Nwy25cZNGEuGYjxwWnai2uW9KNpPb");
    });
    bool status;
    EXPECT_NO_THROW({
       status = cryptoApi->verifySignature(core::Buffer::from("data"), sign, "L5vkdRVHpz99Wohor79hWczzv7LmWAoVQ3axynJ7fQATA7szwGWe");
    });
    EXPECT_EQ(status, true);
} 

TEST_F(CryptoTest, generatePrivateKey) {
    std::string keyInWIF;
    EXPECT_NO_THROW({
        keyInWIF = cryptoApi->generatePrivateKey(std::nullopt);
    });
    EXPECT_NO_THROW({
        privmx::endpoint::core::PrivateKey::fromWIF(keyInWIF);
    });
}

TEST_F(CryptoTest, derivePrivateKey) {
    std::string keyInWIF;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    EXPECT_NO_THROW({
        keyInWIF = cryptoApi->derivePrivateKey("pass","salt");
    });
#pragma GCC diagnostic pop
    EXPECT_NO_THROW({
        privmx::endpoint::core::PrivateKey::fromWIF(keyInWIF);
    });
    EXPECT_EQ(keyInWIF, "L2TUveYrXgohLcLVcvrYd48Nwy25cZNGEuGYjxwWnai2uW9KNpPb");
}

TEST_F(CryptoTest, derivePrivateKey2) {
    std::string keyInWIF;
    EXPECT_NO_THROW({
        keyInWIF = cryptoApi->derivePrivateKey2("pass","salt");
    });
    EXPECT_NO_THROW({
        privmx::endpoint::core::PrivateKey::fromWIF(keyInWIF);
    });
    EXPECT_EQ(keyInWIF, "L1PtGzD2iLGT3vPQkDGqKhrYCxjBQzfnVzG1D4cTuGnPvPqZEtTP");
}

TEST_F(CryptoTest, derivePublicKey) {
    if (!isSecp256k1Build()) GTEST_SKIP() << "fixed secp256k1 vector; this build generates other keys";
    EXPECT_THROW({
        cryptoApi->derivePublicKey("L5vkdRVHpz99Wohor79hWczzv7LmWAoVQ3axynJ7fQATA7szwGWe");
    }, core::Exception);
    std::string keyInBase58DER;
    EXPECT_NO_THROW({
        keyInBase58DER = cryptoApi->derivePublicKey("L2TUveYrXgohLcLVcvrYd48Nwy25cZNGEuGYjxwWnai2uW9KNpPb");
    });
    EXPECT_NO_THROW({
        privmx::endpoint::core::PublicKey::fromBase58DER(keyInBase58DER);
    });
    EXPECT_EQ(keyInBase58DER, "L5vkdRVHpz99Wohor79hWczzv7LmWAoVQ3axynJ7fQATA7szwGWe");
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

/**
 * A 2.x blob used to be pinned here and had to open. It no longer does, and that is the point:
 * 3.0.0 carries no backward compatibility, so `decryptDataSymmetric` reads one format — the
 * suite-tagged frame, whose tag is authenticated. The old `CipherType` byte was not, which is
 * exactly the downgrade surface a second reachable format brings with it.
 */
TEST_F(CryptoTest, decryptDataSymmetric_refusesA2xBlob) {
    const std::string key = privmx::utils::Hex::toString(
        "3ad696c8c37f286adbbd66b2f31e90041850ae2d3ec30250020c0209085f8c62"
    );
    const std::string legacy = privmx::utils::Hex::toString(
        "0478d6fcdf5be68f5ea8af3029ef637bcbc785d94c3064d008e67f6bd2a7c6669a05219eba9963e53571c782ea17eee476"
    );

    EXPECT_ANY_THROW(
        cryptoApi->decryptDataSymmetric(core::Buffer::from(legacy), core::Buffer::from(key))
    );
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
        privmx::endpoint::core::PrivateKey::fromWIF(keyInWIF);
    });
    EXPECT_EQ(keyInWIF, "KyASahKYZjCyKJBB7ixVQbrQ7o56Vxo2PJgCuTL3YLFGBqxfPFAC");
}

TEST_F(CryptoTest, convertPGPAsn1KeyToBase58DERKey) {
    std::string keyInBase58DER;
    EXPECT_NO_THROW({
        keyInBase58DER = cryptoApi->convertPGPAsn1KeyToBase58DERKey(_PGPkey);
    });
    EXPECT_NO_THROW({
        privmx::endpoint::core::PublicKey::fromBase58DER(keyInBase58DER);
    });
    EXPECT_EQ(keyInBase58DER, "L5vBUKhJ9qrxwTwuHd7AYiaVRRQJVKsbYFpbkF6KsrF1wzq3tQbQ");
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

/**
 * Round-tripped through the API rather than fed fixed strings, so the test says what it means — that
 * what the type exports, it can read back — instead of pinning an envelope twice. One exact value is
 * still pinned, in ExtKey_getPrivatePartAsBase58, to catch the format changing by accident.
 */
TEST_F(CryptoTest, ExtKey_fromBase58) {
    const privmx::endpoint::crypto::ExtKey source =
        privmx::endpoint::crypto::ExtKey::fromSeed(core::Buffer::from(_BIP39_seed_withPassword));

    privmx::endpoint::crypto::ExtKey ext_key;
    EXPECT_NO_THROW({ ext_key = privmx::endpoint::crypto::ExtKey::fromBase58(source.getPrivatePartAsBase58()); });
    EXPECT_EQ(source.getPrivateKey(), ext_key.getPrivateKey());

    EXPECT_NO_THROW({ ext_key = privmx::endpoint::crypto::ExtKey::fromBase58(source.getPublicPartAsBase58()); });
    EXPECT_EQ(source.getPublicKey(), ext_key.getPublicKey());
}

/// A BIP-32 `xprv` is no longer this type's format, and has to be refused rather than misread.
TEST_F(CryptoTest, ExtKey_fromBase58_rejectsBip32Envelope) {
    EXPECT_THROW(
        {
            privmx::endpoint::crypto::ExtKey::fromBase58(
                "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
            );
        },
        core::Exception
    );
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
    EXPECT_EQ(privatePart, _ExtKey_privatePartAsBase58_withPassword);
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
    EXPECT_EQ(publicPart, _ExtKey_publicPartAsBase58_withPassword);
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
    EXPECT_EQ(publicKey,_BIP39_publicKeyBase58DER_withPassword_untaggedExtKey);
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
    privmx::endpoint::core::PrivateKey key = privmx::endpoint::core::PrivateKey::fromWIF(_BIP39_privateKeyWIF_withPassword);
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
    if (!isSecp256k1Build()) GTEST_SKIP() << "fixed secp256k1 vector; this build generates other keys";
    privmx::endpoint::crypto::ExtKey ext_key;
    EXPECT_NO_THROW({
        ext_key =  privmx::endpoint::crypto::ExtKey::fromSeed(core::Buffer::from(_BIP39_seed_withPassword));
    });
    auto privateKey = privmx::endpoint::core::PrivateKey::fromWIF(ext_key.getPrivateKey());
    auto sign = privateKey.signToCompactSignatureWithHash("test");
    EXPECT_TRUE(ext_key.verifyCompactSignatureWithHash(core::Buffer::from("test"), core::Buffer::from(sign)));
}

TEST_F(CryptoTest, ExtKey_isPrivate) {
    const privmx::endpoint::crypto::ExtKey source =
        privmx::endpoint::crypto::ExtKey::fromSeed(core::Buffer::from(_BIP39_seed_withoutPassword));
    EXPECT_TRUE(source.isPrivate());

    privmx::endpoint::crypto::ExtKey ext_key;
    EXPECT_NO_THROW({ ext_key = privmx::endpoint::crypto::ExtKey::fromBase58(source.getPrivatePartAsBase58()); });
    EXPECT_TRUE(ext_key.isPrivate());

    EXPECT_NO_THROW({ ext_key = privmx::endpoint::crypto::ExtKey::fromBase58(source.getPublicPartAsBase58()); });
    EXPECT_FALSE(ext_key.isPrivate());
}

TEST_F(CryptoTest, ExtKey_privateKey_operation_on_publicKey) {
    privmx::endpoint::crypto::ExtKey extKeyRandom = privmx::endpoint::crypto::ExtKey::generateRandom();
    std::string publicPartAsBase58 = extKeyRandom.getPublicPartAsBase58();
    privmx::endpoint::crypto::ExtKey extKey = privmx::endpoint::crypto::ExtKey::fromBase58(publicPartAsBase58);
    EXPECT_THROW({
        extKey.derive(4);
    }, core::Exception);
    EXPECT_THROW({
        extKey.deriveHardened(4);
    }, core::Exception);
    EXPECT_THROW({
        extKey.getPrivatePartAsBase58();
    }, core::Exception);
    EXPECT_THROW({
        extKey.getPrivateKey();
    }, core::Exception);
    EXPECT_THROW({
        extKey.getPrivateEncKey();
    }, core::Exception);
}