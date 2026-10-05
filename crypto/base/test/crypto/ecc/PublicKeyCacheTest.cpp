/*
Covers the memo in front of `PublicKey::fromBase58DER`: that a hit is indistinguishable from a parse, that a
malformed key still throws and leaves nothing behind, that the table stays bounded, and that the one table
is shared by every thread — the last of these is what makes a key warmed on an event-pool thread a hit
everywhere else, and is also why concurrent use has to stay consistent.
*/

#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/crypto/ecc/PublicKeyCache.hpp>

using namespace std;

namespace privmx {
namespace crypto {
namespace {

string makeKey() {
    return PrivateKey::generateRandom().getPublicKey().toBase58DER();
}

TEST(PublicKeyCacheTest, HitReturnsTheSameKeyAsAParse) {
    PublicKeyCache::getInstance()->clear();
    const string base58 = makeKey();

    const PublicKey parsed = PublicKey::fromBase58DER(base58);
    const PublicKey first = PublicKeyCache::getInstance()->fromBase58DER(base58);
    const PublicKey second = PublicKeyCache::getInstance()->fromBase58DER(base58);

    EXPECT_EQ(first, parsed);
    EXPECT_EQ(second, parsed);
    EXPECT_EQ(first.toBase58DER(), base58);
    EXPECT_EQ(second.toBase58DER(), base58);
}

TEST(PublicKeyCacheTest, DistinctKeysDoNotCollide) {
    PublicKeyCache::getInstance()->clear();
    const string a = makeKey();
    const string b = makeKey();
    ASSERT_NE(a, b);

    EXPECT_EQ(PublicKeyCache::getInstance()->fromBase58DER(a).toBase58DER(), a);
    EXPECT_EQ(PublicKeyCache::getInstance()->fromBase58DER(b).toBase58DER(), b);
    EXPECT_EQ(PublicKeyCache::getInstance()->fromBase58DER(a).toBase58DER(), a);
    EXPECT_EQ(PublicKeyCache::getInstance()->size(), 2u);
}

TEST(PublicKeyCacheTest, MalformedKeyThrowsAndIsNotCached) {
    PublicKeyCache::getInstance()->clear();

    EXPECT_ANY_THROW(PublicKeyCache::getInstance()->fromBase58DER("not-a-key"));
    EXPECT_EQ(PublicKeyCache::getInstance()->size(), 0u);
    // A second attempt must fail the same way rather than hit a poisoned entry.
    EXPECT_ANY_THROW(PublicKeyCache::getInstance()->fromBase58DER("not-a-key"));
    EXPECT_EQ(PublicKeyCache::getInstance()->size(), 0u);
}

TEST(PublicKeyCacheTest, StaysBoundedWhileKeepingRecentEntriesCorrect) {
    PublicKeyCache::getInstance()->clear();
    vector<string> keys;
    // Past two full generations, so at least one swap and one drop has happened.
    for (int i = 0; i < 400; i++) {
        keys.push_back(makeKey());
        PublicKeyCache::getInstance()->fromBase58DER(keys.back());
    }

    EXPECT_LE(PublicKeyCache::getInstance()->size(), 256u);
    // Whatever survived or was evicted, every key still resolves to itself.
    for (const string& key : keys) {
        EXPECT_EQ(PublicKeyCache::getInstance()->fromBase58DER(key).toBase58DER(), key);
    }
}

// What the per-thread variant could not give: an event delivered on a pool thread warms the key for the
// application thread too, instead of each one paying its own parse.
TEST(PublicKeyCacheTest, OneTableIsSharedByAllThreads) {
    PublicKeyCache::getInstance()->clear();
    const string key = makeKey();
    PublicKeyCache::getInstance()->fromBase58DER(key);
    ASSERT_EQ(PublicKeyCache::getInstance()->size(), 1u);

    size_t sizeSeenByWorker = 0;
    string derSeenByWorker;
    thread worker([&] {
        sizeSeenByWorker = PublicKeyCache::getInstance()->size();
        derSeenByWorker = PublicKeyCache::getInstance()->fromBase58DER(key).toBase58DER();
    });
    worker.join();

    EXPECT_EQ(sizeSeenByWorker, 1u);
    EXPECT_EQ(derSeenByWorker, key);
    EXPECT_EQ(PublicKeyCache::getInstance()->size(), 1u);
}

TEST(PublicKeyCacheTest, ConcurrentMissesOnDistinctKeysAllLand) {
    PublicKeyCache::getInstance()->clear();
    vector<string> keys;
    for (int i = 0; i < 8; i++) {
        keys.push_back(makeKey());
    }

    vector<thread> threads;
    for (const string& key : keys) {
        threads.emplace_back([&key] { PublicKeyCache::getInstance()->fromBase58DER(key); });
    }
    for (thread& t : threads) {
        t.join();
    }

    EXPECT_EQ(PublicKeyCache::getInstance()->size(), keys.size());
    for (const string& key : keys) {
        EXPECT_EQ(PublicKeyCache::getInstance()->fromBase58DER(key).toBase58DER(), key);
    }
}

TEST(PublicKeyCacheTest, ConcurrentUseOfTheSameKeyIsConsistent) {
    PublicKeyCache::getInstance()->clear();
    const string base58 = makeKey();

    vector<thread> threads;
    vector<string> results(8);
    for (size_t i = 0; i < results.size(); i++) {
        threads.emplace_back([&, i] {
            for (int round = 0; round < 50; round++) {
                results[i] = PublicKeyCache::getInstance()->fromBase58DER(base58).toBase58DER();
            }
        });
    }
    for (thread& t : threads) {
        t.join();
    }

    for (const string& der : results) {
        EXPECT_EQ(der, base58);
    }
}

} // namespace
} // namespace crypto
} // namespace privmx
