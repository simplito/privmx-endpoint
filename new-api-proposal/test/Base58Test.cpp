#include <gtest/gtest.h>

#include <string>
#include <iostream>

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"

#include "CryptoProviderRegistry.hpp"
#include "CryptoProviderFromDriver.hpp"
#include "Utils.hpp"
#include "Base58.hpp"

using privmx::cryptoservice::CryptoProviderRegistry;
using privmx::cryptoservice::ICryptoProvider;
using privmx::cryptoservice::Bytes;
using privmx::cryptoservice::ecc::Base58;
using privmx::cryptoservice::ecc::Utils;

TEST(Base58Test, EncodeDecode) {
    const uint data_size = 50;     
    // const uint test_no = 100;
    std::shared_ptr<ICryptoProvider> fromDriver
         = std::make_shared<privmx::cryptoservice::CryptoProviderFromDriver>();
    CryptoProviderRegistry::set(fromDriver);

    Bytes data = CryptoProviderRegistry::get().randomBytes(data_size);
    std::string a(Utils::b2s(data));
    std::string b(Utils::b2s(Base58::decodeB(Base58::encodeB(data))));
    std::string c(Base58::decode(Base58::encode(Utils::b2s(data))));

    EXPECT_STREQ(reinterpret_cast<char*> (a.data()), reinterpret_cast<char*> (c.data()));

    EXPECT_STREQ(reinterpret_cast<char*> (a.data()), reinterpret_cast<char*> (b.data()));
}

TEST(Base58Test, EncodeDecodeWithChecksum) {
    const uint data_size = 50;     
    // const uint test_no = 100;
    std::shared_ptr<ICryptoProvider> fromDriver
         = std::make_shared<privmx::cryptoservice::CryptoProviderFromDriver>();
    CryptoProviderRegistry::set(fromDriver);

    Bytes data = CryptoProviderRegistry::get().randomBytes(data_size);
    std::string a(Utils::b2s(data));

    std::string c(Base58::decode(Base58::encode(Utils::b2s(data))));
    EXPECT_STREQ(reinterpret_cast<char*> (a.data()), reinterpret_cast<char*> (c.data()));

    std::string b(Utils::b2s(Base58::decodeB(Base58::encodeB(data))));
    EXPECT_STREQ(reinterpret_cast<char*> (a.data()), reinterpret_cast<char*> (b.data()));

    std::string e(Base58::decodeWithChecksum(Base58::encodeWithChecksum(Utils::b2s(data))));
    EXPECT_STREQ(reinterpret_cast<char*> (a.data()), reinterpret_cast<char*> (e.data()));

    std::string d(Utils::b2s(Base58::decodeWithChecksumB(fromDriver, Base58::encodeWithChecksumB(fromDriver, data))));
    EXPECT_STREQ(reinterpret_cast<char*> (a.data()), reinterpret_cast<char*> (d.data()));

    std::string f(Base58::decodeWithChecksum(Utils::b2s(Base58::encodeWithChecksumB(fromDriver, data))));
    EXPECT_STREQ(reinterpret_cast<char*> (a.data()), reinterpret_cast<char*> (f.data()));

    std::string g(Utils::b2s(Base58::decodeWithChecksumB(fromDriver, Utils::s2b(Base58::encodeWithChecksum(Utils::b2s(data))))));
    EXPECT_STREQ(reinterpret_cast<char*> (a.data()), reinterpret_cast<char*> (g.data()));

}

