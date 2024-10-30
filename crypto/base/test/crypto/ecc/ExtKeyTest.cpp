#include <string>
#include <gtest/gtest.h>

#include <privmx/crypto/ecc/ExtKey.hpp>
#include <privmx/utils/Utils.hpp>

using namespace std;

namespace privmx {
namespace crypto {
namespace {

// Test vectors from https://en.bitcoin.it/wiki/BIP_0032

TEST(ExtKeyTest, TestVector1) {
    string seed("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);

    ExtKey key1 = ExtKey::fromSeed(seed);

    EXPECT_EQ(key1.getPublicPartAsBase58(), "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
    EXPECT_EQ(key1.getPrivatePartAsBase58(), "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");

    ExtKey key2 = key1.deriveHardened(0);

    EXPECT_EQ(key2.getPublicPartAsBase58(), "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");
    EXPECT_EQ(key2.getPrivatePartAsBase58(), "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");

    ExtKey key3 = key2.derive(1);

    EXPECT_EQ(key3.getPublicPartAsBase58(), "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ");
    EXPECT_EQ(key3.getPrivatePartAsBase58(), "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs");

    ExtKey key4 = key3.deriveHardened(2);

    EXPECT_EQ(key4.getPublicPartAsBase58(), "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5");
    EXPECT_EQ(key4.getPrivatePartAsBase58(), "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM");

    ExtKey key5 = key2.derive(1).deriveHardened(2).derive(2);

    EXPECT_EQ(key5.getPublicPartAsBase58(), "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV");
    EXPECT_EQ(key5.getPrivatePartAsBase58(), "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334");

    ExtKey key6 = key5.derive(1000000000);

    EXPECT_EQ(key6.getPublicPartAsBase58(), "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy");
    EXPECT_EQ(key6.getPrivatePartAsBase58(), "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76");
}

TEST(ExtKeyTest, TestVector2) {
    string seed("\xff\xfc\xf9\xf6\xf3\xf0\xed\xea\xe7\xe4\xe1\xde\xdb\xd8\xd5\xd2\xcf\xcc\xc9\xc6\xc3\xc0\xbd\xba\xb7\xb4\xb1\xae\xab\xa8\xa5\xa2"
        "\x9f\x9c\x99\x96\x93\x90\x8d\x8a\x87\x84\x81\x7e\x7b\x78\x75\x72\x6f\x6c\x69\x66\x63\x60\x5d\x5a\x57\x54\x51\x4e\x4b\x48\x45\x42", 64);

    ExtKey key1 = ExtKey::fromSeed(seed);

    EXPECT_EQ(key1.getPublicPartAsBase58(), "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");
    EXPECT_EQ(key1.getPrivatePartAsBase58(), "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U");

    ExtKey key2 = key1.derive(0);

    EXPECT_EQ(key2.getPublicPartAsBase58(), "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH");
    EXPECT_EQ(key2.getPrivatePartAsBase58(), "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt");

    ExtKey key3 = key2.deriveHardened(2147483647);

    EXPECT_EQ(key3.getPublicPartAsBase58(), "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a");
    EXPECT_EQ(key3.getPrivatePartAsBase58(), "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9");

    ExtKey key4 = key3.derive(1);

    EXPECT_EQ(key4.getPublicPartAsBase58(), "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon");
    EXPECT_EQ(key4.getPrivatePartAsBase58(), "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef");

    ExtKey key5 = key4.deriveHardened(2147483646);

    EXPECT_EQ(key5.getPublicPartAsBase58(), "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL");
    EXPECT_EQ(key5.getPrivatePartAsBase58(), "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc");

    ExtKey key6 = key5.derive(2);

    EXPECT_EQ(key6.getPublicPartAsBase58(), "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt");
    EXPECT_EQ(key6.getPrivatePartAsBase58(), "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j");
}

TEST(ExtKeyTest, TestVector3) {
    string seed("\x4b\x38\x15\x41\x58\x3b\xe4\x42\x33\x46\xc6\x43\x85\x0d\xa4\xb3\x20\xe4\x6a\x87\xae\x3d\x2a\x4e\x6d\xa1\x1e\xba\x81\x9c\xd4\xac"
        "\xba\x45\xd2\x39\x31\x9a\xc1\x4f\x86\x3b\x8d\x5a\xb5\xa0\xd0\xc6\x4d\x2e\x8a\x1e\x7d\x14\x57\xdf\x2e\x5a\x3c\x51\xc7\x32\x35\xbe", 64);

    ExtKey key1 = ExtKey::fromSeed(seed);

    EXPECT_EQ(key1.getPublicPartAsBase58(), "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13");
    EXPECT_EQ(key1.getPrivatePartAsBase58(), "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6");

    ExtKey key2 = key1.deriveHardened(0);

    EXPECT_EQ(key2.getPublicPartAsBase58(), "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y");
    EXPECT_EQ(key2.getPrivatePartAsBase58(), "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L");
}

TEST(ExtKeyTest, TestVector4) {
    string seed("\x3d\xdd\x56\x02\x28\x58\x99\xa9\x46\x11\x45\x06\x15\x7c\x79\x97\xe5\x44\x45\x28\xf3\x00\x3f\x61\x34\x71\x21\x47\xdb\x19\xb6\x78", 32);

    ExtKey key1 = ExtKey::fromSeed(seed);

    EXPECT_EQ(key1.getPublicPartAsBase58(), "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa");
    EXPECT_EQ(key1.getPrivatePartAsBase58(), "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv");

    ExtKey key2 = key1.deriveHardened(0);

    EXPECT_EQ(key2.getPublicPartAsBase58(), "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m");
    EXPECT_EQ(key2.getPrivatePartAsBase58(), "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G");

    ExtKey key3 = key2.deriveHardened(1);

    EXPECT_EQ(key3.getPublicPartAsBase58(), "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt");
    EXPECT_EQ(key3.getPrivatePartAsBase58(), "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1");
}

// Privmx versions (with no leading zeros) of TestVector3 and TestVector4

TEST(ExtKeyTest, TestVector3_OldPrivmxVersion) {
    string seed("\x4b\x38\x15\x41\x58\x3b\xe4\x42\x33\x46\xc6\x43\x85\x0d\xa4\xb3\x20\xe4\x6a\x87\xae\x3d\x2a\x4e\x6d\xa1\x1e\xba\x81\x9c\xd4\xac"
        "\xba\x45\xd2\x39\x31\x9a\xc1\x4f\x86\x3b\x8d\x5a\xb5\xa0\xd0\xc6\x4d\x2e\x8a\x1e\x7d\x14\x57\xdf\x2e\x5a\x3c\x51\xc7\x32\x35\xbe", 64);

    ExtKey key1 = ExtKey::fromSeed(seed);

    EXPECT_EQ(key1.getPublicPartAsBase58(), "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13");
    EXPECT_EQ(key1.getPrivatePartAsBase58(), "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6");

    ExtKey key2 = key1.deriveHardenedOldPrivmxVersion(0);

    EXPECT_EQ(key2.getPublicPartAsBase58(), "xpub68NZiKmJWnxxQxVnXFin746wmPga9MCMj8AGJB1KwYWXdnVnyzUQxSSbJzeTrVdUgirdq4JWwm68R3s9YZPMZ271N1MCo2MxKHpMgXzuVjR");
    EXPECT_EQ(key2.getPrivatePartAsBase58(), "xprv9uPDJpEQgRQfCURKREBmjvADDMr5jtUWMuEfVnbiPCyYkzAeSTAAQe87TiqnSGEsmyzNG87rqVGs9hcYbRYV383aMDhE1cAGGLf6HaiozTW");
}

TEST(ExtKeyTest, TestVector4_OldPrivmxVersion) {
    string seed("\x3d\xdd\x56\x02\x28\x58\x99\xa9\x46\x11\x45\x06\x15\x7c\x79\x97\xe5\x44\x45\x28\xf3\x00\x3f\x61\x34\x71\x21\x47\xdb\x19\xb6\x78", 32);

    ExtKey key1 = ExtKey::fromSeed(seed);

    EXPECT_EQ(key1.getPublicPartAsBase58(), "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa");
    EXPECT_EQ(key1.getPrivatePartAsBase58(), "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv");

    ExtKey key2 = key1.deriveHardenedOldPrivmxVersion(0);

    EXPECT_EQ(key2.getPublicPartAsBase58(), "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m");
    EXPECT_EQ(key2.getPrivatePartAsBase58(), "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G");

    ExtKey key3 = key2.deriveHardenedOldPrivmxVersion(1);

    EXPECT_EQ(key3.getPublicPartAsBase58(), "xpub6BJA1jSqiukebSvcTC3mVUTP3x9duojWSyE3oqPT8nYHEW1SHS3Zf3Y9BTvLv5S3Dnrh4CSBbGBhWt1yqB3hL4aDtF3N8foHHNr2YQgZGac");
    EXPECT_EQ(key3.getPrivatePartAsBase58(), "xprv9xJocDuwtYCMNxr9MAWm8LWeVvK9WM1f5kJT1SyqaT1JMhgHjtjK7FDfLEQSr1nGu5eBfTS75ZkTs6L8PR8gE6Wb3A8DZeNA3X3m8FQ2qHx");
}

} // namespace
} // namespace crypto
} // namespace privmx
