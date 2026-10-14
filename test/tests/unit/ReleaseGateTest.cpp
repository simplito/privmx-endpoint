/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * m2 (A5-F3): the client releases at most one statement per prevDigest while the first could still be applied by an
 * honest bridge. The gate alone; GroupApiLyingBridgeTest covers its wiring into GroupApiImpl.
 */

#include <gtest/gtest.h>

#include <privmx/endpoint/core/ReleaseGate.hpp>

using privmx::endpoint::core::ReleaseGate;
using Verdict = ReleaseGate::Verdict;

namespace {

constexpr std::uint64_t W = 20 * 60 * 1000;
constexpr std::uint64_t T0 = 1'700'000'000'000;
const std::string G = "group";

ReleaseGate::Released at(
    std::uint64_t seq,
    const std::string& prev,
    const std::string& digest,
    bool yields = false,
    std::uint64_t date = T0
) {
    return ReleaseGate::Released{.seq = seq, .prevDigest = prev, .digest = digest, .date = date, .yields = yields};
}

} // namespace

TEST(ReleaseGate, SECURITY_NoSecondStatementIsReleasedAtAPrevDigestWhileOneIsUnresolved) {
    ReleaseGate gate(W);
    ASSERT_EQ(gate.check(G, at(2, "P", "S1"), T0, 1), Verdict::Ok);
    gate.record(G, at(2, "P", "S1"));
    EXPECT_EQ(gate.check(G, at(2, "P", "S2"), T0 + 1, 1), Verdict::Held) << "a second statement at P";
    EXPECT_EQ(gate.check(G, at(2, "P", "S1"), T0 + 1, 1), Verdict::Ok) << "a resend of the same statement";
    EXPECT_EQ(gate.check("other", at(2, "P", "S2"), T0 + 1, 1), Verdict::Ok) << "another chain";
}

TEST(ReleaseGate, SECURITY_AnUnresolvedStatementBlocksOnlyForItsAcceptanceWindow) {
    ReleaseGate gate(W);
    gate.record(G, at(2, "P", "S1"));
    EXPECT_EQ(gate.check(G, at(2, "P", "S2"), T0 + W - 1, 1), Verdict::Held);
    EXPECT_EQ(gate.check(G, at(2, "P", "S2"), T0 + W, 1), Verdict::Ok);

    // Dated ahead of the clock (N-1 clamps to the head's date): the window runs from the signed date.
    ReleaseGate ahead(W);
    ahead.record(G, at(2, "P", "S1", false, T0 + W));
    EXPECT_EQ(ahead.check(G, at(2, "P", "S2"), T0 + W, 1), Verdict::Held);
    EXPECT_EQ(ahead.check(G, at(2, "P", "S2"), T0 + 2 * W - 1, 1), Verdict::Held);
    EXPECT_EQ(ahead.check(G, at(2, "P", "S2"), T0 + 2 * W, 1), Verdict::Ok);
}

TEST(ReleaseGate, SECURITY_AnUnresolvedStatementIsDroppedOnceThePinReachesItsSeq) {
    ReleaseGate gate(W);
    gate.record(G, at(2, "P", "S1"));
    ASSERT_TRUE(gate.unresolved(G, T0, 1).has_value());
    EXPECT_FALSE(gate.unresolved(G, T0, 2).has_value());
    EXPECT_EQ(gate.check(G, at(3, "S1", "S3"), T0, 2), Verdict::Ok);
}

TEST(ReleaseGate, SECURITY_APlanBehindThePinIsStale) {
    ReleaseGate gate(W);
    EXPECT_EQ(gate.check(G, at(2, "P", "S2"), T0, 2), Verdict::Stale) << "no entry, still behind the pin";
    EXPECT_EQ(gate.check(G, at(1, "", "S1"), T0, 2), Verdict::Stale);
    gate.record(G, at(2, "P", "S1"));
    EXPECT_EQ(gate.check(G, at(2, "P", "S1"), T0, 2), Verdict::Stale) << "landed: a resend is pointless too";
}

TEST(ReleaseGate, SECURITY_ASelfUpdateYieldsOnlyToAStatementThatIsNotASelfUpdate) {
    ReleaseGate gate(W);
    gate.record(G, at(2, "P", "Ssu", true));
    EXPECT_EQ(gate.check(G, at(2, "P", "Sop"), T0, 1), Verdict::Ok) << "an op supersedes a background self-update";
    EXPECT_EQ(gate.check(G, at(2, "P", "Ssu2", true), T0, 1), Verdict::Held) << "a second self-update at P";

    ReleaseGate op(W);
    op.record(G, at(2, "P", "Sop"));
    EXPECT_EQ(op.check(G, at(2, "P", "Ssu", true), T0, 1), Verdict::Held);
    EXPECT_EQ(op.check(G, at(2, "P", "Sop2"), T0, 1), Verdict::Held);
}

TEST(ReleaseGate, SECURITY_AtOneSeqTheNonYieldingEntryIsKept) {
    const auto su = at(2, "P", "Ssu", true);
    const auto op = at(2, "P", "Sop");
    EXPECT_TRUE(ReleaseGate::newer(op, su));
    EXPECT_FALSE(ReleaseGate::newer(su, op));
    for (const bool opFirst : {false, true}) {
        ReleaseGate gate(W);
        gate.record(G, opFirst ? op : su);
        gate.record(G, opFirst ? su : op);
        const auto kept = gate.unresolved(G, T0, 1);
        ASSERT_TRUE(kept.has_value());
        EXPECT_EQ(kept->digest, "Sop");
        EXPECT_EQ(gate.check(G, at(2, "P", "S3"), T0, 1), Verdict::Held);
    }
}

TEST(ReleaseGate, SECURITY_OpKeysOfDifferentOperationsNeverCollide) {
    EXPECT_NE(ReleaseGate::opKey("remove", {std::string("a\0b", 3)}), ReleaseGate::opKey("remove", {"a", "b"}));
    EXPECT_NE(
        ReleaseGate::opKey("add", {"ab", "user", "K", "c", "user", "K"}),
        ReleaseGate::opKey("add", {"a", "buser", "K", "c", "user", "K"})
    );
    EXPECT_NE(ReleaseGate::opKey("ab"), ReleaseGate::opKey("a", {"b"}));
    EXPECT_NE(ReleaseGate::opKey("remove", {}), ReleaseGate::opKey("remove", {""}));
    EXPECT_EQ(ReleaseGate::opKey("remove", {"a", "b"}), ReleaseGate::opKey("remove", {"a", "b"}));
}
