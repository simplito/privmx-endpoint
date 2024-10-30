#include <string>
#include <gtest/gtest.h>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/utils/Utils.hpp>

using namespace std;

namespace privmx {
namespace crypto {
namespace {

TEST(PrivateKeyTest, FromWifAndToWif) {
    const string wif1("L1YwTwAr8dQCBzfmXBzh6ggBkYbLuu15Tc7s4bajrRNDbsogs9a5");
    const string wif2("KwDzTrBejZw91hSpkoauVYnjgkm64DAb3UX1QBCRjf5BryiVK6jk");
    const string wif3("KwDiK7diMWJYFDV6pPbQ8BzgWznPa4evLqKwLncDpeMrEZA5E2Xp");
    const string wif4("KwDkPqYKx8R2zEPTP6QnPLsvYSwsqeCJKHsJ6GWncC3r4CaqViRB");

    const string expected_priv1("\x81\x3d\xe0\x0e\xb4\x3c\x22\x7e\xaf\x82\x47\x40\xbc\xee\x66\xf8\xb8\xe4\xc0\x83\x83\x34\x83\x65\x8c\x8c\x65\xe7\xd9\xcd\x76\xc9", 32);
    const string expected_priv2("\x00\x24\xf6\xbb\xb1\x0a\x74\xd9\x0a\xeb\xbc\xc3\xf4\xf1\x8a\x86\xda\xb8\x6c\x81\x51\x3b\x4a\x3b\x9d\x28\xe8\x26\xd6\xa7\x9a\x97", 32);
    const string expected_priv3("\x00\x00\x4a\xbc\x31\xdf\x4a\x0e\xc4\x9a\xec\x9e\xfa\x6d\xce\x2e\x6b\x3d\xa3\x99\x85\x6f\x13\xd0\xef\x56\x07\x6b\x62\x84\xab\x4d", 32);
    const string expected_priv4("\x00\x05\x04\x9f\x90\xde\x17\x9b\xb2\x6d\x66\x90\xdc\x68\x2d\xed\xb7\xcd\xa5\x03\x0b\x93\x7b\xd8\x7c\x65\x36\xdd\x46\x2a\x58\xf3", 32);

    PrivateKey priv1 = PrivateKey::fromWIF(wif1);
    PrivateKey priv2 = PrivateKey::fromWIF(wif2);
    PrivateKey priv3 = PrivateKey::fromWIF(wif3);
    PrivateKey priv4 = PrivateKey::fromWIF(wif4);

    EXPECT_EQ(priv1.getPrivateEncKey(), expected_priv1);
    EXPECT_EQ(priv1.toWIF(), wif1);
    EXPECT_EQ(priv2.getPrivateEncKey(), expected_priv2);
    EXPECT_EQ(priv2.toWIF(), wif2);
    EXPECT_EQ(priv3.getPrivateEncKey(), expected_priv3);
    EXPECT_EQ(priv3.toWIF(), wif3);
    EXPECT_EQ(priv4.getPrivateEncKey(), expected_priv4);
    EXPECT_EQ(priv4.toWIF(), wif4);
}

} // namespace
} // namespace crypto
} // namespace privmx
