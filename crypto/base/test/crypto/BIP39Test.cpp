#include <string>
#include <gtest/gtest.h>
#include <algorithm>
#include <privmx/crypto/BIP39.hpp>

using namespace std;

namespace privmx {
namespace crypto {
namespace {

TEST(Bip39ImplTest, Test) {

    const string e1("\x61\x67\xe1\xb4\x91\x56\x63\xa0\x5a\xfb\x4d\x1b\xd2\xd5\xde\xe8", 16);
    const string e2("\x41\xca\x41\xc5\x12\x80\x41\xe4\xe6\x9e\xa0\x4d\x0f\x33\x01\xda\x0c\x5c\x33\x2d", 20);
    const string e3("\x70\xf6\x48\x39\x22\x4c\x69\xcc\x9b\x38\x94\x1a\x99\xe5\xad\xf8\xa6\x2b\x66\xbc\x82\xf5\x04\x38", 24);
    const string e4("\xc6\xce\x89\x2b\x5c\xad\x8c\x28\xa9\x1e\x69\x19\xc6\x8c\x19\x35\x78\x1f\xb9\x2f\x77\x4d\xa8\x96\x64\x33\x86\x85", 28);
    const string e5("\xed\xf1\x0c\xf0\x55\xd9\xf9\x06\xaf\x60\x3d\x5f\x66\xea\xd2\x1e\x02\x43\x74\xb3\x72\xc6\x9a\xea\x31\xc3\xd4\x18\xda\xf3"
                    "\x76\x20", 32);
    const string m1("gesture disease honey cargo great south hip have bridge note jeans spatial");
    const string m2("dove faith image celery advice venue omit staff escape kangaroo scatter reduce shift book result");
    const string m3("ill rather atom duty shoot town hollow barely box song hidden vanish glance rebuild velvet gadget aerobic shine");
    const string m4("short inmate enlist rich sugar begin piece snake border crucial alien helmet limit symptom saddle trust possible rebel "
                    "artefact artist fruit");
    const string m5("unknown mask despair produce panel local rural amateur garage dance region despair category ripple soccer flee online "
                    "face ill popular misery keen sudden bonus");
    const string s1("\xe7\xd5\x87\x9d\x7d\x7e\xc4\xd5\x93\xb8\xb0\xce\x59\xd1\x71\xd6\xda\x53\x28\x61\x60\x6a\x07\xe4\x3d\xcd\x61\xbb\x9a\x4e"
                    "\x6d\x24\x47\xcd\xa5\xab\x0a\x41\x55\x1c\xc1\xc2\x5b\xc2\xa4\x33\x44\x62\xe5\x1e\x5e\xef\x21\xda\x06\x1a\xd9\x29\xad\xd2"
                    "\x8a\xfc\x2a\x90", 64);
    const string s2("\x00\xf6\xfc\x14\x34\xab\x2e\xfe\xd8\x97\xd8\x26\x6d\xb6\xc3\x3d\x0c\x86\x78\xe4\x24\x2f\x07\x3b\xb9\x8e\x81\xca\x2d\x1d"
                    "\x00\x9e\xc1\x6f\x91\x62\x03\xcd\x1a\x23\x79\x10\x5d\x12\xe7\x92\x38\xb3\x54\xc8\xe7\x59\xbb\xae\xb0\x9a\x66\x9d\x14\x56"
                    "\x58\xf0\x1a\x4e", 64);
    const string s3("\x2f\xcc\x42\xf1\x27\x87\x80\xd4\x3a\xdd\x53\x1c\xc6\x26\x9a\xe0\x71\xd3\x8e\x4b\x6f\x95\x28\xd7\x7c\xd4\x4c\x0c\x95\xff"
                    "\x7b\x65\x38\x7c\xb3\x0a\x2e\x62\x4c\x4f\x73\xfa\x7c\x13\xb0\xf4\xc0\xab\xea\x5b\xa4\xc4\x04\xfd\x2b\xd5\xc0\x30\x10\xeb"
                    "\x97\xa5\x30\xd1", 64);
    const string s4("\xe6\xb5\xb0\xbf\x2e\x07\xfa\x1a\x6a\x88\x1b\x76\x9d\x13\x5a\xcb\x18\x0b\xe3\x79\x1a\xdd\x0b\x53\xc4\x1a\x77\x4f\xad\xf6"
                    "\xc2\x58\x03\x4c\x1b\x19\x7e\xce\x37\x41\x51\x9d\x1d\x02\x4c\xad\x67\xe9\xac\x82\xe6\x54\x56\x62\xa7\x1d\xfd\x69\xc9\x43"
                    "\xbd\x50\x7c\x8a", 64);
    const string s5("\x98\x38\xda\x4b\x53\x98\x60\xde\x11\x3e\xc3\xe3\x47\x6d\xa8\xd6\x12\x45\xcd\x26\xe2\xd9\x26\xbb\x67\x5b\xee\x65\x98\xf7"
                    "\xff\xec\x8b\x94\xa3\x4e\xfc\xa3\x95\x06\x65\xfe\xa8\x02\x5b\x37\x51\xa7\xe8\x45\x93\x10\x9f\xea\x0b\xa3\xda\xeb\xa9\xdd"
                    "\x11\x92\x72\xc8", 64);

    auto rm1 = Bip39Impl::entropyToMnemonic(e1);
    auto rm2 = Bip39Impl::entropyToMnemonic(e2);
    auto rm3 = Bip39Impl::entropyToMnemonic(e3);
    auto rm4 = Bip39Impl::entropyToMnemonic(e4);
    auto rm5 = Bip39Impl::entropyToMnemonic(e5);

    EXPECT_EQ(rm1, m1);
    EXPECT_EQ(rm2, m2);
    EXPECT_EQ(rm3, m3);
    EXPECT_EQ(rm4, m4);
    EXPECT_EQ(rm5, m5);

    auto re1 = Bip39Impl::mnemonicToEntropy(m1);
    auto re2 = Bip39Impl::mnemonicToEntropy(m2);
    auto re3 = Bip39Impl::mnemonicToEntropy(m3);
    auto re4 = Bip39Impl::mnemonicToEntropy(m4);
    auto re5 = Bip39Impl::mnemonicToEntropy(m5);

    EXPECT_EQ(re1, e1);
    EXPECT_EQ(re2, e2);
    EXPECT_EQ(re3, e3);
    EXPECT_EQ(re4, e4);
    EXPECT_EQ(re5, e5);

    auto rs1 = Bip39Impl::mnemonicToSeed(m1);
    auto rs2 = Bip39Impl::mnemonicToSeed(m2);
    auto rs3 = Bip39Impl::mnemonicToSeed(m3);
    auto rs4 = Bip39Impl::mnemonicToSeed(m4);
    auto rs5 = Bip39Impl::mnemonicToSeed(m5);

    EXPECT_EQ(rs1, s1);
    EXPECT_EQ(rs2, s2);
    EXPECT_EQ(rs3, s3);
    EXPECT_EQ(rs4, s4);
    EXPECT_EQ(rs5, s5);

}


} // namespace
} // namespace crypto
} // namespace privmx
