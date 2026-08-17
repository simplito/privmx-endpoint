#include <gtest/gtest.h>

#include <string>
#include <iostream>

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"

#include "CryptoProviderRegistry.hpp"
#include "CryptoProviderFromDriver.hpp"

using privmx::cryptoservice::CryptoProviderRegistry;
using privmx::cryptoservice::ICryptoProvider;
using privmx::cryptoservice::Bytes;

// Verify size of the obtained data vector
TEST(DigestTest, Size) {
    const uint test_no = 100;
    std::shared_ptr<ICryptoProvider> fromDriver
         = std::make_shared<privmx::cryptoservice::CryptoProviderFromDriver>();
    CryptoProviderRegistry::set(fromDriver);

    for (int n = 1; n <= test_no; n++) {
        Bytes b = CryptoProviderRegistry::get().randomBytes(n);
        EXPECT_EQ(b.size(), n);
    }
}

// Verify the uniqueness of obtained data vector
TEST(DigestTest, Uniqueness) {
    const uint test_no = 100;
    const uint size = 5; 
    std::shared_ptr<ICryptoProvider> fromDriver
         = std::make_shared<privmx::cryptoservice::CryptoProviderFromDriver>();
    CryptoProviderRegistry::set(fromDriver);

    for (int n = 1; n <= test_no; n++) {
        Bytes a = CryptoProviderRegistry::get().randomBytes(size+1);
        Bytes b = CryptoProviderRegistry::get().randomBytes(size+1);
        a[size]=0;
        b[size]=0;
        EXPECT_STRNE(reinterpret_cast<char*> (a.data()), reinterpret_cast<char*> (b.data()));
    }
}