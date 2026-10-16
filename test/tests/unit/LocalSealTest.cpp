/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * 01: the core of the local state. What the application's store holds is sealed under the identity key and bound to
 * its slot, read back only if it opens, and written by compare-and-swap so that two instances of one device never
 * overwrite each other's state.
 */

#include <gtest/gtest.h>

#include <condition_variable>
#include <thread>

#include <Poco/JSON/Array.h>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/BigEndian.hpp>
#include <privmx/endpoint/core/LocalSeal.hpp>
#include <privmx/endpoint/core/varinterface/VarPinStoreInterface.hpp>

#include "MemoryPinStore.hpp"

namespace core = privmx::endpoint::core;
using privmx::crypto::PrivateKey;

namespace {

const std::string LABEL = "privmx/test";
const std::string SLOT = "test/scope/me";

// A body that lists names, one lp each; the merge every test saver uses (adds its own name).
std::string withName(const std::optional<std::string>& body, const std::string& name) {
    std::string out = body.value_or("");
    core::bigendian::putLp(out, name);
    return out;
}

std::set<std::string> namesIn(const std::string& body) {
    std::set<std::string> names;
    core::bigendian::Reader in(body);
    while (!in.done()) {
        names.insert(in.lp());
    }
    return names;
}

} // namespace

TEST(LocalSeal, ASealedBodyOpensUnderItsKeyLabelAndSlot) {
    const PrivateKey me = PrivateKey::generateRandom();
    const std::string blob = core::sealLocal(me, LABEL, 1, SLOT, "body");
    EXPECT_EQ(core::openLocal(me, LABEL, 1, SLOT, blob), std::optional<std::string>("body"));
    EXPECT_EQ(core::openLocal(me, LABEL, 1, SLOT, core::sealLocal(me, LABEL, 1, SLOT, "")), std::optional<std::string>(""));
}

TEST(LocalSeal, SECURITY_ABlobWithAnyByteChangedIsIgnored) {
    const PrivateKey me = PrivateKey::generateRandom();
    const std::string blob = core::sealLocal(me, LABEL, 1, SLOT, "some pins");
    for (std::size_t i = 0; i < blob.size(); ++i) {
        std::string changed = blob;
        changed[i] = static_cast<char>(changed[i] ^ 0x01);
        EXPECT_EQ(core::openLocal(me, LABEL, 1, SLOT, changed), std::nullopt) << "byte " << i;
    }
    EXPECT_EQ(core::openLocal(me, LABEL, 1, SLOT, blob.substr(0, blob.size() - 1)), std::nullopt);
    EXPECT_EQ(core::openLocal(me, LABEL, 1, SLOT, blob + "x"), std::nullopt);
    EXPECT_EQ(core::openLocal(me, LABEL, 1, SLOT, std::string(32, '\0')), std::nullopt) << "shorter than a tag";
}

TEST(LocalSeal, SECURITY_ABlobSealedUnderAnotherIdentityOrLabelIsIgnored) {
    const PrivateKey me = PrivateKey::generateRandom();
    const std::string blob = core::sealLocal(PrivateKey::generateRandom(), LABEL, 1, SLOT, "planted");
    EXPECT_EQ(core::openLocal(me, LABEL, 1, SLOT, blob), std::nullopt);
    EXPECT_EQ(core::openLocal(me, "privmx/other", 1, SLOT, core::sealLocal(me, LABEL, 1, SLOT, "x")), std::nullopt);
}

TEST(LocalSeal, SECURITY_ABlobMovedToAnotherSlotIsIgnored) {
    // Another identity's, Bridge's or kind's slot: the slot key is in the MAC.
    const PrivateKey me = PrivateKey::generateRandom();
    const std::string blob = core::sealLocal(me, LABEL, 1, "group-pins/bridgeA/me", "pins");
    EXPECT_EQ(core::openLocal(me, LABEL, 1, "group-pins/bridgeB/me", blob), std::nullopt);
    EXPECT_EQ(core::openLocal(me, LABEL, 1, "commit-released/bridgeA/me", blob), std::nullopt);
}

TEST(LocalSeal, ABlobOfAnotherVersionIsIgnored) {
    const PrivateKey me = PrivateKey::generateRandom();
    EXPECT_EQ(core::openLocal(me, LABEL, 1, SLOT, core::sealLocal(me, LABEL, 2, SLOT, "v2")), std::nullopt);
}

TEST(LocalSeal, BigEndianReaderRefusesOverrun) {
    std::string bytes;
    core::bigendian::putU32(bytes, 1000); // a length far past the end
    bytes += "abc";
    core::bigendian::Reader in(bytes);
    EXPECT_THROW(in.lp(), std::out_of_range);
    core::bigendian::Reader numbers(std::string(3, '\0'));
    EXPECT_THROW(numbers.u32(), std::out_of_range);
    std::string round;
    core::bigendian::putU8(round, 7);
    core::bigendian::putU64(round, 0x0102030405060708ULL);
    core::bigendian::putLp(round, "x");
    core::bigendian::Reader back(round);
    EXPECT_EQ(back.u8(), 7);
    EXPECT_EQ(back.u64(), 0x0102030405060708ULL);
    EXPECT_EQ(back.lp(), "x");
    EXPECT_TRUE(back.done());
}

TEST(LocalSeal, UpdateSealedRetriesOnACompareAndSwapMiss) {
    const PrivateKey me = PrivateKey::generateRandom();
    MemoryPinStore store;
    int merges = 0;
    // A sibling writes between this saver's load and save, once.
    bool raced = false;
    const bool saved = core::updateSealed(store, me, SLOT, LABEL, 1, [&](const std::optional<std::string>& body) {
        ++merges;
        if (!raced) {
            raced = true;
            store.put(SLOT, core::sealLocal(me, LABEL, 1, SLOT, withName(std::nullopt, "sibling")));
        }
        return withName(body, "me");
    });
    EXPECT_TRUE(saved);
    EXPECT_EQ(merges, 2);
    EXPECT_EQ(store.casMisses, 1);
    const auto body = core::openLocal(me, LABEL, 1, SLOT, store.get(SLOT));
    ASSERT_TRUE(body.has_value());
    EXPECT_EQ(namesIn(body.value()), (std::set<std::string>{"sibling", "me"}));
}

TEST(LocalSeal, AnUnopenableStoredBlobReachesTheMergeAsNothing) {
    const PrivateKey me = PrivateKey::generateRandom();
    MemoryPinStore store;
    store.put(SLOT, "garbage");
    std::optional<std::string> seen = std::string("unset");
    EXPECT_TRUE(core::updateSealed(store, me, SLOT, LABEL, 1, [&](const std::optional<std::string>& body) {
        seen = body;
        return std::string("fresh");
    }));
    EXPECT_EQ(seen, std::nullopt);
    EXPECT_EQ(core::openLocal(me, LABEL, 1, SLOT, store.get(SLOT)), std::optional<std::string>("fresh"));
}

TEST(LocalSeal, SECURITY_TwoInterleavedSaversNeverLoseEachOthersEntries) {
    // Both load the empty slot before either saves (a lost update without the CAS); the loser merges again.
    const PrivateKey me = PrivateKey::generateRandom();
    MemoryPinStore store;
    std::mutex m;
    std::condition_variable cv;
    int loaded = 0;
    store.afterLoad = [&](const std::string&) {
        std::unique_lock<std::mutex> lock(m);
        if (++loaded <= 2) {
            cv.notify_all();
            cv.wait_for(lock, std::chrono::seconds(5), [&] { return loaded >= 2; });
        }
    };
    std::thread a([&] {
        core::updateSealed(store, me, SLOT, LABEL, 1, [](const auto& body) { return withName(body, "a"); });
    });
    std::thread b([&] {
        core::updateSealed(store, me, SLOT, LABEL, 1, [](const auto& body) { return withName(body, "b"); });
    });
    a.join();
    b.join();
    const auto body = core::openLocal(me, LABEL, 1, SLOT, store.get(SLOT));
    ASSERT_TRUE(body.has_value());
    EXPECT_EQ(namesIn(body.value()), (std::set<std::string>{"a", "b"}));
    EXPECT_GE(store.casMisses, 1);
}

TEST(LocalSeal, UpdateSealedGivesUpWhenEverySaveMisses) {
    const PrivateKey me = PrivateKey::generateRandom();
    MemoryPinStore store;
    int round = 0;
    EXPECT_FALSE(core::updateSealed(store, me, SLOT, LABEL, 1, [&](const auto& body) {
        store.put(SLOT, std::to_string(++round)); // always moved under the saver
        return withName(body, "me");
    }));
}

TEST(LocalSeal, TheVarStoreCarriesKeysAndBlobsThroughTheCallbacks) {
    // What the C interface's `privmx_endpoint_setPinStore` wraps: binary blobs both ways, null for nothing stored.
    MemoryPinStore backing;
    core::VarSerializer serializer({.addType = false, .binaryFormat = core::VarSerializer::Options::PSON_BINARYSTRING});
    core::VarDeserializer deserializer;
    core::VarPinStoreInterface store(
        [&](const Poco::Dynamic::Var& args) -> Poco::Dynamic::Var {
            const auto array = args.extract<Poco::JSON::Array::Ptr>();
            const std::string blob = backing.load(array->get(0).convert<std::string>()).stdString();
            return blob.empty() ? Poco::Dynamic::Var() : serializer.serialize(core::Buffer::from(blob));
        },
        [&](const Poco::Dynamic::Var& args) -> Poco::Dynamic::Var {
            const auto array = args.extract<Poco::JSON::Array::Ptr>();
            return backing.save(
                array->get(0).convert<std::string>(), deserializer.deserialize<core::Buffer>(array->get(1), "blob"),
                deserializer.deserialize<core::Buffer>(array->get(2), "expected")
            );
        },
        deserializer, serializer
    );
    const std::string binary("a\0b\xff", 4);
    EXPECT_TRUE(store.load("k").stdString().empty());
    EXPECT_TRUE(store.save("k", core::Buffer::from(binary), core::Buffer()));
    EXPECT_EQ(store.load("k").stdString(), binary);
    EXPECT_FALSE(store.save("k", core::Buffer::from("x"), core::Buffer())) << "a compare-and-swap miss";
    EXPECT_EQ(backing.get("k"), binary);
}
