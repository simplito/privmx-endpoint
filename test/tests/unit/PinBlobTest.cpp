/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * 01: the body of the `group-pins` slot and the merge rule two instances of one device save by. The codec must keep
 * every field a pin is checked by, refuse anything malformed, and never drop a record to fit its budget; the merge
 * must never let one instance's record silently replace a different history another instance verified.
 */

#include <gtest/gtest.h>

#include <chrono>
#include <iostream>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/BigEndian.hpp>
#include <privmx/endpoint/core/LocalSeal.hpp>
#include <privmx/endpoint/group/keytree/PinBlob.hpp>

namespace core = privmx::endpoint::core;
using namespace privmx::endpoint::group::keytree;
using Pin = TreeVerifier::Pin;
using PinSet = TreeVerifier::PinSet;
using Case = PinBlob::Case;

namespace {

Pin pinAt(std::uint64_t seq, const std::string& digest, std::uint64_t seenAt = 1) {
    Pin pin;
    pin.seq = seq;
    pin.digest = digest;
    pin.date = 1000 + seq;
    pin.roster = TreeVerifier::Roster{.users = {"alice", "bob"}, .managers = {"carol"}, .hash = "RH" + digest};
    pin.keyVersion = 2;
    pin.groupPubKey = "GPK";
    pin.rosterVersion = 3;
    pin.rules = GroupRules{
        .creator = "carol",
        .update = "manager",
        .rotateKeys = "user",
        .updatePolicy = "owner",
        .ownerCanBeRemovedFromManagers = "no",
        .hash = "PH"
    };
    pin.treeHash = "TH" + digest;
    pin.contextId = "ctx";
    pin.generations = {{1, 4}, {3, 7}};
    pin.refusedSeq = 0;
    pin.seenAt = seenAt;
    return pin;
}

PinSet roundTrip(const PinSet& pins) {
    const auto decoded = PinBlob::decode(PinBlob::encode(pins));
    EXPECT_TRUE(decoded.has_value());
    return decoded.value_or(PinSet{});
}

void expectSameRecord(const Pin& a, const Pin& b, bool full) {
    EXPECT_EQ(a.contextId, b.contextId);
    EXPECT_EQ(a.seq, b.seq);
    EXPECT_EQ(a.digest, b.digest);
    EXPECT_EQ(a.date, b.date);
    EXPECT_EQ(a.keyVersion, b.keyVersion);
    EXPECT_EQ(a.groupPubKey, b.groupPubKey);
    EXPECT_EQ(a.rosterVersion, b.rosterVersion);
    EXPECT_EQ(a.roster.hash, b.roster.hash);
    EXPECT_EQ(a.rules.creator, b.rules.creator);
    EXPECT_EQ(a.rules.update, b.rules.update);
    EXPECT_EQ(a.rules.rotateKeys, b.rules.rotateKeys);
    EXPECT_EQ(a.rules.updatePolicy, b.rules.updatePolicy);
    EXPECT_EQ(a.rules.ownerCanBeRemovedFromManagers, b.rules.ownerCanBeRemovedFromManagers);
    EXPECT_EQ(a.rules.hash, b.rules.hash);
    EXPECT_EQ(a.treeHash, b.treeHash);
    EXPECT_EQ(a.refusedSeq, b.refusedSeq);
    EXPECT_EQ(a.seenAt, b.seenAt);
    EXPECT_EQ(a.forked, b.forked);
    EXPECT_EQ(b.hasRoster, full);
    if (full) {
        EXPECT_EQ(a.roster.users, b.roster.users);
        EXPECT_EQ(a.roster.managers, b.roster.managers);
        EXPECT_EQ(a.generations, b.generations);
    } else {
        EXPECT_TRUE(b.roster.users.empty());
        EXPECT_TRUE(b.generations.empty());
    }
}

// A valid body with one record, whose flags byte is replaced by `flags`.
std::string bodyWithFlags(std::uint8_t flags) {
    PinSet pins;
    Pin compact = pinAt(5, "D5");
    compact.hasRoster = false;
    pins.tree["g"] = compact;
    std::string body = PinBlob::encode(pins);
    body.back() = static_cast<char>(flags); // a compact record ends with its flags byte
    return body;
}

std::optional<std::pair<std::uint64_t, std::string>> at(const Pin& pin) {
    return std::make_pair(pin.seq, pin.digest);
}

} // namespace

TEST(PinBlob, RoundTripKeepsEveryField) {
    PinSet pins;
    pins.tree["full"] = pinAt(9, "D9", 5);
    Pin compact = pinAt(4, "D4", 3);
    compact.hasRoster = false;
    compact.roster.users.clear();
    compact.roster.managers.clear();
    compact.generations.clear();
    pins.tree["compact"] = compact;
    Pin forked = pinAt(7, "D7", 2);
    forked.forked = true;
    forked.refusedSeq = 8;
    pins.tree["forked"] = forked;
    Pin lostRace;
    lostRace.refusedSeq = 3;
    pins.tree["lostRace"] = lostRace;
    pins.planes["full"] = {3, 4, 5};
    pins.planes["planesOnly"] = {1, 2, 3};

    const PinSet back = roundTrip(pins);
    ASSERT_EQ(back.tree.size(), 4u);
    expectSameRecord(pins.tree.at("full"), back.tree.at("full"), true);
    expectSameRecord(pins.tree.at("compact"), back.tree.at("compact"), false);
    expectSameRecord(pins.tree.at("forked"), back.tree.at("forked"), true);
    EXPECT_EQ(back.tree.at("lostRace").seq, 0u);
    EXPECT_EQ(back.tree.at("lostRace").refusedSeq, 3u);
    EXPECT_EQ(back.planes, pins.planes);
    EXPECT_FALSE(back.tree.at("full").synced.has_value()) << "memory-only fields are not stored";
}

TEST(PinBlob, SECURITY_ALengthPastTheEndIsRefused) {
    // A body the seal accepts (it was written by a key holder) is still parsed strictly: never past its end.
    PinSet pins;
    pins.tree["g"] = pinAt(5, "D5");
    const std::string body = PinBlob::encode(pins);
    for (std::size_t cut = 0; cut < body.size(); ++cut) {
        EXPECT_EQ(PinBlob::decode(body.substr(0, cut)), std::nullopt) << "cut at " << cut;
    }
    EXPECT_EQ(PinBlob::decode(body + "x"), std::nullopt) << "trailing bytes";
    std::string lying;
    core::bigendian::putU32(lying, 1);
    core::bigendian::putU32(lying, 0xFFFFFFF0); // a group id longer than the body
    EXPECT_EQ(PinBlob::decode(lying), std::nullopt);
}

TEST(PinBlob, UnknownFlagBitsAreRefused) {
    EXPECT_TRUE(PinBlob::decode(bodyWithFlags(0)).has_value());
    EXPECT_TRUE(PinBlob::decode(bodyWithFlags(4)).has_value()); // forked
    EXPECT_EQ(PinBlob::decode(bodyWithFlags(8)), std::nullopt);
    EXPECT_EQ(PinBlob::decode(bodyWithFlags(0x80)), std::nullopt);
    std::string nodesWithoutRoster = bodyWithFlags(2);
    EXPECT_EQ(PinBlob::decode(nodesWithoutRoster), std::nullopt);
}

TEST(PinBlob, UnsortedOrDuplicateGroupsAreRefused) {
    PinSet one;
    one.tree["b"] = pinAt(5, "D5");
    PinSet other;
    other.tree["a"] = pinAt(5, "D5");
    // Two bodies spliced: "b" then "a", and "b" twice.
    const std::string b = PinBlob::encode(one).substr(4);
    const std::string a = PinBlob::encode(other).substr(4);
    std::string unsorted;
    core::bigendian::putU32(unsorted, 2);
    EXPECT_EQ(PinBlob::decode(unsorted + b + a), std::nullopt);
    EXPECT_EQ(PinBlob::decode(unsorted + b + b), std::nullopt);
    EXPECT_TRUE(PinBlob::decode(unsorted + a + b).has_value());
}

TEST(PinBlob, SECURITY_NoRecordIsDroppedByTheBudget) {
    // A bridge that makes the client verify many groups can push rosters out of the blob, never a pin: the old
    // group G stays (compact), and the most recent rosters are kept in full.
    PinSet pins;
    pins.tree["G"] = pinAt(3, "DG", 1);
    Pin huge = pinAt(2, "DH", 100000);
    for (int i = 0; i < 70000; ++i) {
        huge.roster.users.insert("user-" + std::to_string(i) + std::string(10, 'x'));
    }
    pins.tree["huge"] = huge;
    for (int i = 0; i < 5000; ++i) {
        pins.tree["g" + std::to_string(i)] = pinAt(2, "D" + std::to_string(i), 10 + i);
    }
    const std::string body = PinBlob::encode(pins);
    EXPECT_LE(body.size(), PinBlob::BUDGET);
    const PinSet back = roundTrip(pins);
    EXPECT_EQ(back.tree.size(), pins.tree.size());
    ASSERT_EQ(back.tree.count("G"), 1u);
    EXPECT_EQ(back.tree.at("G").seq, 3u);
    EXPECT_EQ(back.tree.at("G").digest, "DG");
    EXPECT_FALSE(back.tree.at("huge").hasRoster) << "a roster above the budget is not kept";
    EXPECT_TRUE(back.tree.at("g4999").hasRoster) << "the most recent rosters are";
    EXPECT_FALSE(back.tree.at("G").hasRoster) << "the oldest is the first to go compact";
}

TEST(PinBlob, DecideCoversEveryRow) {
    const Pin p9 = pinAt(9, "D9");
    Pin m = pinAt(10, "D10");
    Pin r = pinAt(10, "D10");
    // a: nothing stored
    EXPECT_EQ(PinBlob::decide(&m, nullptr), Case::TakeMine);
    // b: nothing in memory
    EXPECT_EQ(PinBlob::decide(nullptr, &r), Case::TakeStored);
    // c: either forked, or another context
    Pin forked = r;
    forked.forked = true;
    EXPECT_EQ(PinBlob::decide(&m, &forked), Case::Fork);
    Pin elsewhere = r;
    elsewhere.contextId = "other";
    EXPECT_EQ(PinBlob::decide(&m, &elsewhere), Case::Fork);
    // d: one state
    EXPECT_EQ(PinBlob::decide(&m, &r), Case::Same);
    // e: memory never synced, still its first contact here, and the slot holds a later record
    Pin r11 = pinAt(11, "D11");
    Pin tofu = m;
    tofu.firstContact = true;
    EXPECT_EQ(PinBlob::decide(&tofu, &r11), Case::TakeStored);
    // f: a link pending
    Pin pending = m;
    pending.synced = at(p9);
    pending.unlinked = std::make_shared<const Pin>(r11);
    EXPECT_EQ(PinBlob::decide(&pending, &r11), Case::Pending);
    // g: the slot is what memory last synced with; memory moved on
    m.synced = at(p9);
    EXPECT_EQ(PinBlob::decide(&m, &p9), Case::TakeMine);
    // h1: memory is what it synced; the slot moved past it
    Pin still = p9;
    still.synced = at(p9);
    EXPECT_EQ(PinBlob::decide(&still, &r11), Case::TakeStored);
    // h2: memory is what it synced; the slot went back (local storage rolled back)
    Pin p5 = pinAt(5, "D5");
    EXPECT_EQ(PinBlob::decide(&still, &p5), Case::TakeMine);
    // i: both moved since the sync, to one seq with two digests
    Pin other10 = pinAt(10, "D10'");
    EXPECT_EQ(PinBlob::decide(&m, &other10), Case::Fork);
    // j: both moved since the sync, to different seqs
    Pin r12 = pinAt(12, "D12");
    EXPECT_EQ(PinBlob::decide(&m, &r12), Case::Unlinked);

    // The slot's side of each row.
    const auto merged = [](const Pin& mine, const Pin& stored) {
        PinSet a, b;
        a.tree["g"] = mine;
        b.tree["g"] = stored;
        return PinBlob::mergeForSave(a, b).tree.at("g");
    };
    EXPECT_EQ(merged(m, p9).digest, "D10");            // g: mine
    EXPECT_EQ(merged(still, r11).digest, "D11");       // h1: stored
    EXPECT_EQ(merged(still, p5).digest, "D9");         // h2: mine
    EXPECT_TRUE(merged(m, other10).forked);            // i: stored, forked
    EXPECT_EQ(merged(m, other10).digest, "D10'");
    EXPECT_EQ(merged(m, r12).digest, "D12");           // j: stored, unmarked until the link
    EXPECT_FALSE(merged(m, r12).forked);
    EXPECT_EQ(merged(pending, r11).digest, "D11");     // f: stored
}

TEST(PinBlob, SECURITY_ANeverSyncedPinIsReplacedOnlyWhileStillItsFirstContact) {
    // A pin taken by first contact stays unsynced until its first save, and may move meanwhile (an own removal, a
    // verified step). A sibling's record must not then replace it: the two are linked by hash (row j), and one seq
    // with two digests is a fork (row i). Base: row e took the record whatever it was, below the own removal.
    const Pin p9 = pinAt(9, "D9");
    const Pin r11 = pinAt(11, "D11");
    Pin moved = pinAt(10, "D10"); // first contact at 9 here, then the own removal at 10
    EXPECT_EQ(PinBlob::decide(&moved, &p9), Case::Unlinked);
    EXPECT_EQ(PinBlob::decide(&moved, &r11), Case::Unlinked);
    const Pin other10 = pinAt(10, "D10'");
    EXPECT_EQ(PinBlob::decide(&moved, &other10), Case::Fork);
    Pin tofu = moved;
    tofu.firstContact = true;
    EXPECT_EQ(PinBlob::decide(&tofu, &p9), Case::Unlinked) << "a first contact is never lowered either";
    EXPECT_EQ(PinBlob::decide(&tofu, &other10), Case::Fork);
    PinSet mine, stored;
    mine.tree["g"] = moved;
    stored.tree["g"] = p9;
    EXPECT_EQ(PinBlob::mergeForSave(mine, stored).tree.at("g").digest, "D9") << "the slot keeps R until the link";
}

TEST(PinBlob, SECURITY_ASeqZeroRecordNeverReplacesAPin) {
    // A plane-only or lost-race-only entry carries no tree state; on either side it cannot displace a verified pin.
    const Pin pin = pinAt(7, "D7");
    Pin lostRace;
    lostRace.refusedSeq = 9;
    EXPECT_EQ(PinBlob::decide(&pin, &lostRace), Case::TakeMine);
    EXPECT_EQ(PinBlob::decide(&lostRace, &pin), Case::TakeStored);
    PinSet mine, stored;
    mine.tree["g"] = pin;
    stored.tree["g"] = lostRace;
    const Pin kept = PinBlob::mergeForSave(mine, stored).tree.at("g");
    EXPECT_EQ(kept.seq, 7u);
    EXPECT_EQ(kept.digest, "D7");
    EXPECT_EQ(kept.refusedSeq, 9u) << "but its refusal is kept";
}

TEST(PinBlob, MergeTakesTheHigherGenerationsAndPlaneCounters) {
    Pin mine = pinAt(7, "D7");
    mine.generations = {{1, 5}, {2, 1}};
    mine.refusedSeq = 3;
    Pin stored = pinAt(7, "D7");
    stored.generations = {{1, 4}, {2, 6}, {5, 2}};
    stored.seenAt = 99;
    PinSet a, b;
    a.tree["g"] = mine;
    b.tree["g"] = stored;
    a.planes["g"] = {5, 1, 9};
    b.planes["g"] = {4, 3, 2};
    b.planes["h"] = {1, 1, 1};
    const PinSet merged = PinBlob::mergeForSave(a, b);
    EXPECT_EQ(merged.tree.at("g").generations, (std::map<std::uint32_t, std::uint32_t>{{1, 5}, {2, 6}, {5, 2}}));
    EXPECT_EQ(merged.tree.at("g").refusedSeq, 3u);
    EXPECT_EQ(merged.tree.at("g").seenAt, 99u);
    EXPECT_EQ(merged.planes.at("g"), (std::array<std::int64_t, 3>{5, 3, 9}));
    EXPECT_EQ(merged.planes.at("h"), (std::array<std::int64_t, 3>{1, 1, 1}));

    // A compact record in memory keeps the slot's roster when both are one state.
    Pin compact = mine;
    compact.hasRoster = false;
    compact.roster.users.clear();
    a.tree["g"] = compact;
    EXPECT_TRUE(PinBlob::mergeForSave(a, b).tree.at("g").hasRoster);
}

TEST(PinBlob, EncodeTiming) {
    // Not asserting: encode, decode and seal of 1k and 5k pins, and of 3 groups of 16k members, printed.
    const auto identity = privmx::crypto::PrivateKey::generateRandom();
    const auto time = [&](const std::string& name, const PinSet& pins) {
        const auto start = std::chrono::steady_clock::now();
        const std::string body = PinBlob::encode(pins);
        const auto encoded = std::chrono::steady_clock::now();
        const std::string blob = core::sealLocal(identity, PinBlob::LABEL, PinBlob::VERSION, "slot", body);
        const auto sealed = std::chrono::steady_clock::now();
        const auto opened = core::openLocal(identity, PinBlob::LABEL, PinBlob::VERSION, "slot", blob);
        ASSERT_TRUE(opened.has_value());
        ASSERT_TRUE(PinBlob::decode(opened.value()).has_value());
        const auto decoded = std::chrono::steady_clock::now();
        const auto ms = [](auto a, auto b) { return std::chrono::duration<double, std::milli>(b - a).count(); };
        std::cout << "[pins] " << name << ": " << body.size() << " B, encode " << ms(start, encoded) << " ms, seal "
                  << ms(encoded, sealed) << " ms, open+decode " << ms(sealed, decoded) << " ms" << std::endl;
    };
    for (const int count : {1000, 5000}) {
        PinSet pins;
        for (int i = 0; i < count; ++i) {
            pins.tree["group-" + std::to_string(i)] = pinAt(3, "D" + std::to_string(i), i);
        }
        time(std::to_string(count) + " pins", pins);
    }
    PinSet large;
    for (int g = 0; g < 3; ++g) {
        Pin pin = pinAt(3, "D" + std::to_string(g), g);
        for (int i = 0; i < 16384; ++i) {
            pin.roster.users.insert("user-" + std::to_string(i));
        }
        large.tree["large-" + std::to_string(g)] = pin;
    }
    time("3 groups of 16k members", large);
}
