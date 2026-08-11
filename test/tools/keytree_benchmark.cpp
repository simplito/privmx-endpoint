/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * ⚠️ EPHEMERAL — BENCHMARK, NOT FOR MERGE. Revert along with crypto/CryptoOpStats.hpp and its call sites.
 *
 * Measures what each group operation actually costs, in crypto operations rather than in wall-clock time: machine
 * speed varies, operation counts are a property of the design. Timings are reported too, but as a sanity check on
 * the counts.
 *
 * Everything runs in-process with real EC keys, real ECIES and the production tree/ladder code. No bridge is
 * involved, and it is not needed: every operation's cost is client-side cryptography, and the server's own work is
 * integer comparison over node indices. What the numbers here do *not* include is network round trips.
 *
 * A group of `N` members granted access to a thread is modelled exactly as the implementation does it:
 *
 *   - the thread's content key (CK) is wrapped **once** to the group's grant public key (the tree case), or
 *     **once per member** (the flat case, i.e. how it worked before the tree)
 *   - reading content means resolving the grant key for the epoch the content was written at: climb the tree, then
 *     descend the Epoch Ladder if that epoch is not the current one
 *   - sending a message is symmetric work under CK, independent of group size
 *
 * Optimistic and pessimistic are reported separately throughout, because for several operations they differ by
 * three orders of magnitude and an average would hide both:
 *
 *   - **optimistic** — a warm client (has already climbed, so node and epoch keys are cached), a removal whose
 *     path is cached, a read of current content, a descent that can use skip rungs
 *   - **pessimistic** — a cold client (empty key store, must climb from its leaf), a read of the *oldest* content,
 *     and a ladder built without skip rungs so the descent is forced through every intermediate epoch
 *
 * Usage: keytree_benchmark [members=16384] [epochs=1024]
 */

#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <algorithm>
#include <functional>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/CryptoOpStats.hpp>
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/utils/Base58.hpp>

#include <privmx/endpoint/group/keytree/LadderKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>
#include <privmx/endpoint/group/keytree/TreeWire.hpp>

using privmx::crypto::CryptoOpStats;
using privmx::crypto::PrivateKey;
using privmx::crypto::PublicKey;
using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;

namespace {

using Clock = std::chrono::steady_clock;

struct Measurement {
    std::string label;
    CryptoOpStats::Snapshot ops;
    double millis = 0;
    std::string note;
    /** Set when the operation did not succeed — its counts then measure a failure, not a cost. */
    std::string failure;
    /** A heading rather than a measurement. */
    bool section = false;
};

std::vector<Measurement> results;

/** Inserts a heading into the report, so the table reads as sections rather than as one long list. */
void section(const std::string& title) {
    results.push_back(Measurement{"── " + title + " ──", {}, 0, "", "", true});
}

/**
 * Runs `body`, recording the crypto operations it performed and how long it took.
 *
 * `body` returns an empty string on success or a reason for failure. A failed operation's counts describe how far
 * it got before giving up, which is not a cost and must not be read as one — so the reason is carried into the
 * table rather than left in stderr where a reader would take the row at face value.
 */
template<typename Body>
void measure(const std::string& label, const std::string& note, Body&& body) {
    const auto before = CryptoOpStats::read();
    const auto start = Clock::now();
    const std::string failure = body();
    const double millis = std::chrono::duration<double, std::milli>(Clock::now() - start).count();
    results.push_back(Measurement{label, CryptoOpStats::since(before), millis, note, failure});
    std::cout << "  done: " << label << " (" << std::fixed << std::setprecision(0) << millis << " ms)"
              << (failure.empty() ? "" : "  !! " + failure) << "\n"
              << std::flush;
}

std::string withThousands(std::uint64_t value) {
    std::string digits = std::to_string(value);
    std::string out;
    int count = 0;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        if (count > 0 && count % 3 == 0) {
            out.push_back(' ');
        }
        out.push_back(*it);
        ++count;
    }
    return std::string(out.rbegin(), out.rend());
}

/** Columns actually used by at least one row, so an empty primitive does not eat a column. */
std::vector<CryptoOpStats::Op> activeColumns() {
    std::vector<CryptoOpStats::Op> active;
    for (std::size_t i = 0; i < CryptoOpStats::OpCount; ++i) {
        const auto op = static_cast<CryptoOpStats::Op>(i);
        for (const Measurement& row : results) {
            if (row.ops.get(op) > 0) {
                active.push_back(op);
                break;
            }
        }
    }
    return active;
}

void printDetailedTable() {
    const std::vector<CryptoOpStats::Op> columns = activeColumns();
    const int labelWidth = 46;

    std::cout << "\n" << std::string(labelWidth, '=') << " PER-PRIMITIVE BREAKDOWN "
              << std::string(30, '=') << "\n\n";
    std::cout << std::left << std::setw(labelWidth) << "operation";
    for (const auto op : columns) {
        std::cout << std::right << std::setw(10) << CryptoOpStats::name(op);
    }
    std::cout << std::right << std::setw(11) << "ASYM" << std::setw(10) << "sym" << std::setw(11) << "ms" << "\n";
    std::cout << std::string(labelWidth + 10 * columns.size() + 32, '-') << "\n";

    for (const Measurement& row : results) {
        if (row.section) {
            std::cout << "\n" << std::left << row.label << "\n";
            continue;
        }
        std::cout << std::left << std::setw(labelWidth) << row.label;
        for (const auto op : columns) {
            const std::uint64_t value = row.ops.get(op);
            std::cout << std::right << std::setw(10) << (value == 0 ? "·" : withThousands(value));
        }
        std::cout << std::right << std::setw(11) << withThousands(row.ops.asymmetric()) << std::setw(10)
                  << withThousands(row.ops.symmetric()) << std::setw(11) << std::fixed << std::setprecision(1)
                  << row.millis << "\n";
        if (!row.failure.empty()) {
            std::cout << "    !! FAILED: " << row.failure << "\n";
        }
        if (!row.note.empty()) {
            std::cout << "       " << row.note << "\n";
        }
    }
}

/** Cost per primitive, measured directly, so the counts above can be turned into an estimated time. */
void printCalibration(std::size_t rounds, const std::vector<TreeMember>& roster) {
    std::cout << "\n" << std::string(46, '=') << " PRIMITIVE COST (calibration) "
              << std::string(25, '=') << "\n\n";
    const std::string payload(64, 'x');
    const std::string key32 = privmx::crypto::Crypto::randomBytes(32);
    const std::string iv = privmx::crypto::Crypto::randomBytes(16);
    const PrivateKey signer = PrivateKey::generateRandom();
    const PublicKey signerPub = signer.getPublicKey();
    const std::string signature = signer.signToCompactSignature(payload);
    const PrivateKey peer = PrivateKey::generateRandom();

    struct Timed {
        std::string name;
        double micros;
    };
    std::vector<Timed> timings;
    const auto time = [&](const std::string& name, const std::function<void()>& body) {
        const auto start = Clock::now();
        for (std::size_t i = 0; i < rounds; ++i) {
            body();
        }
        const double micros =
            std::chrono::duration<double, std::micro>(Clock::now() - start).count() / static_cast<double>(rounds);
        timings.push_back(Timed{name, micros});
    };

    time("keygen", [&] { PrivateKey::generateRandom(); });
    time("ECDH", [&] { signer.derive(peer.getPublicKey()); });
    time("sign", [&] { signer.signToCompactSignature(payload); });
    time("verify", [&] { signerPub.verifyCompactSignature(payload, signature); });
    time("AES-256-CBC enc", [&] { privmx::crypto::Crypto::aes256CbcPkcs7Encrypt(payload, key32, iv); });
    time("HMAC-SHA-256", [&] { privmx::crypto::Crypto::hmacSha256(key32, payload); });
    time("SHA-256", [&] { privmx::crypto::Crypto::sha256(payload); });
    time("SHA-512", [&] { privmx::crypto::Crypto::sha512(payload); });
    time("random 32B", [&] { privmx::crypto::Crypto::randomBytes(32); });

    // ── where a wrap's time actually goes ──
    // A wrap is supposed to be "one ECDH plus small change". These rows check that claim: anything here that is
    // not obviously cheap is doing hidden work, most likely recomputing an EC point or running a big-integer
    // base58 loop on every call.
    const PublicKey recipient = peer.getPublicKey();
    const std::string wif = signer.toWIF();
    const std::string b58 = recipient.toBase58DER();
    const std::string b58raw = recipient.toDER();
    const std::string blob = TreeKeys::wrapKey(signer, recipient, signer);

    time("  priv.getPublicKey()", [&] { signer.getPublicKey(); });
    time("  priv.toWIF()", [&] { signer.toWIF(); });
    time("  PrivateKey::fromWIF()", [&] { PrivateKey::fromWIF(wif); });
    // Splitting fromWIF, because attributing its 600 us to "slow Base58" was a guess: Base58 here is GMP, and
    // encoding measured 1,2 us. The other half of the call is the driver building an EC key from a raw scalar.
    const std::string wifPayload = privmx::utils::Base58::decodeWithChecksum(wif);
    time("    Base58::decodeWithChecksum(WIF)", [&] { privmx::utils::Base58::decodeWithChecksum(wif); });
    time("    Base58::encodeWithChecksum(33B)", [&] { privmx::utils::Base58::encodeWithChecksum(b58raw); });
    time("    Base58::decode (no checksum)", [&] { privmx::utils::Base58::decode(b58); });
    time("  PublicKey::fromDER (decompress)", [&] { PublicKey::fromDER(recipient.toDER()); });
    time("  pub.toBase58DER()", [&] { recipient.toBase58DER(); });
    time("  PublicKey::fromBase58DER()", [&] { PublicKey::fromBase58DER(b58); });
    time("  pub.toDER()", [&] { recipient.toDER(); });
    time("TreeKeys::wrapKey (full)", [&] { TreeKeys::wrapKey(signer, recipient, signer); });
    time("TreeKeys::unwrapKey (full)", [&] { TreeKeys::unwrapKey(blob, peer); });

    // ── copying key objects ──
    // Suspected after an earlier measurement anomaly: leaving a roster copy inside a timed block dominated the
    // result. If a copy really costs as much as an EC operation, the build pays it thousands of times.
    // The sink is written to, so the copy cannot be optimised away — a naive `const auto copy = x; (void)copy;`
    // measured 0.0 us at -O3 purely because the compiler deleted it.
    std::vector<PublicKey> pubSink(8, recipient);
    std::vector<PrivateKey> privSink(8, signer);
    std::size_t sinkIndex = 0;
    time("  copy PublicKey (into a sink)", [&] { pubSink[sinkIndex++ % pubSink.size()] = recipient; });
    time("  copy PrivateKey (into a sink)", [&] { privSink[sinkIndex++ % privSink.size()] = signer; });
    // What the earlier "roster copy" anomaly actually was: building the member-key map, not copying keys.
    // Deliberately few rounds — this one is O(N), and at 200 rounds it alone took twelve minutes.
    {
        const auto start = Clock::now();
        for (int i = 0; i < 3; ++i) {
            TreeKeyStore scratch;
            TreeKeys keys(scratch);
            keys.setMemberKeys(roster);
        }
        timings.push_back(Timed{"  setMemberKeys(full roster)",
                                std::chrono::duration<double, std::micro>(Clock::now() - start).count() / 3.0});
    }

    // ── the decisive check ──
    // `ECC::ECC()` calls `ECCImpl::genPair()`, so a *default-constructed* PublicKey mints a throwaway EC keypair.
    // `std::map::operator[]` default-constructs before assigning; `emplace` does not. Counting keygens does NOT
    // reveal this — the counter sits on `PrivateKey::generateRandom`, and the default constructor reaches
    // `genPair()` directly, below it. So the evidence has to be the time.
    {
        const auto timeInsertions = [&](bool useSubscript) {
            const auto start = Clock::now();
            std::map<std::string, PublicKey> map;
            for (int i = 0; i < 500; ++i) {
                if (useSubscript) {
                    map[std::to_string(i)] = recipient;
                } else {
                    map.emplace(std::to_string(i), recipient);
                }
            }
            return std::chrono::duration<double, std::micro>(Clock::now() - start).count() / 500.0;
        };
        timings.push_back(Timed{"  map[key] = pub (per insert)", timeInsertions(true)});
        timings.push_back(Timed{"  map.emplace(key, pub) (per insert)", timeInsertions(false)});
    }

    double cheapest = timings.front().micros;
    for (const Timed& row : timings) {
        cheapest = std::min(cheapest, row.micros);
    }
    std::cout << std::left << std::setw(24) << "primitive" << std::right << std::setw(12) << "us/op"
              << std::setw(14) << "relative" << "\n";
    std::cout << std::string(50, '-') << "\n";
    for (const Timed& row : timings) {
        std::cout << std::left << std::setw(24) << row.name << std::right << std::setw(12) << std::fixed
                  << std::setprecision(1) << row.micros << std::setw(13) << std::setprecision(0)
                  << (row.micros / cheapest) << "x" << "\n";
    }
    std::cout << "\n(" << rounds << " rounds each; relative to the cheapest primitive measured)\n";
}

/** Names why a descent stopped, so a row that measures a failure says so. */
std::string descentStatus(const DescentResult& descent) {
    if (descent.key.has_value()) {
        return std::string();
    }
    switch (descent.failure) {
        case DescentFailure::TooLong:
            return "hop limit (maxWalk=256) exhausted at epoch " + std::to_string(descent.reachedEpoch)
                + " — this history is UNREACHABLE, not merely slow";
        case DescentFailure::EraBoundary:
            return "stopped at an era floor";
        case DescentFailure::Pruned:
            return "stopped at the prune watermark";
        case DescentFailure::MissingRung:
            return "no rung leads further down";
        case DescentFailure::Tampered:
            return "a recovered key did not match the epoch registry";
        case DescentFailure::NotEntitled:
            return "no starting key held";
        default:
            return "descent produced no key";
    }
}

struct Member {
    std::string userId;
    PrivateKey priv;
};

std::vector<Member> makeMembers(std::uint32_t count) {
    std::vector<Member> members;
    members.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        members.push_back(Member{"u" + std::to_string(i), PrivateKey::generateRandom()});
    }
    return members;
}

std::vector<TreeMember> publicOf(const std::vector<Member>& members) {
    std::vector<TreeMember> result;
    result.reserve(members.size());
    for (const Member& member : members) {
        result.push_back(TreeMember{member.userId, member.priv.getPublicKey()});
    }
    return result;
}

} // namespace

int main(int argc, char** argv) {
    const std::uint32_t memberCount = argc > 1 ? static_cast<std::uint32_t>(std::stoul(argv[1])) : 16384;
    const std::uint32_t epochCount = argc > 2 ? static_cast<std::uint32_t>(std::stoul(argv[2])) : 1024;

    std::cout << "PrivMX group key benchmark\n"
              << "  members : " << withThousands(memberCount) << "\n"
              << "  epochs  : " << withThousands(epochCount) << " (for the history/ladder measurements)\n"
              << "  depth   : " << TreeMath::depth(memberCount) << " (log2 of the member count)\n\n"
              << "Generating member identities...\n"
              << std::flush;

    // Member long-term keypairs are not part of any operation's cost — every member already has one — so they are
    // generated before the first measurement starts.
    const std::vector<Member> members = makeMembers(memberCount);
    const std::vector<TreeMember> roster = publicOf(members);
    const std::string containerKey = privmx::crypto::Crypto::randomBytes(32);

    // ── setup ────────────────────────────────────────────────────────────────
    section("group creation (once)");
    TreeKeyStore ownerStore;
    BuildPlan build;
    measure("create group: build the key tree", "2(N-1)+1 wraps, N-1 node keypairs — once, at creation", [&] {
        TreeKeys builder(ownerStore);
        build = builder.build(roster, members[0].priv);
        return std::string();
    });
    // The same crypto the build performs, with none of its bookkeeping: N-1 keypairs and 2(N-1)+1 wraps into a
    // discarded buffer. The difference against `build` above is what the bookkeeping costs — map insertions,
    // plan vectors, node/edge structs — and it should be near zero.
    measure(
        "create group: SYNTHETIC crypto only (no bookkeeping)",
        "same keygens and wraps as the build, nothing else",
        [&] {
            std::vector<PrivateKey> nodeKeys;
            nodeKeys.reserve(memberCount);
            for (std::uint32_t i = 0; i + 1 < memberCount; ++i) {
                nodeKeys.push_back(PrivateKey::generateRandom());
            }
            std::size_t sink = 0;
            for (std::uint32_t i = 0; i + 1 < memberCount; ++i) {
                sink += TreeKeys::wrapKey(nodeKeys[i], roster[i].publicKey(), members[0].priv).size();
                sink += TreeKeys::wrapKey(nodeKeys[i], roster[(i + 1) % memberCount].publicKey(), members[0].priv).size();
            }
            return sink > 0 ? std::string() : std::string("nothing produced");
        }
    );

    server::GroupTreeState wireTree = TreeWire::fromBuildPlan(build, roster);
    TreeGroupState state = TreeWire::toRuntime(wireTree, 1, build.grantKey.getPublicKey());
    ownerStore.putGrantKey(1, build.grantKey);

    measure("create group, FLAT baseline: key to every member", "what the pre-tree implementation does: N wraps", [&] {
        const PrivateKey flatGroupKey = PrivateKey::generateRandom();
        for (const TreeMember& member : roster) {
            TreeKeys::wrapKey(flatGroupKey, member.publicKey(), members[0].priv);
        }
        return std::string();
    });

    // ── granting a thread access to the group ────────────────────────────────
    // Parsing what the server sends back. A climb needs `depth` node keys, but the conversion deserialises every
    // published node — so this is paid in full on every read of a tree-backed group.
    measure("parse the served tree state (all N-1 nodes)", "toRuntime: one point decompression per node", [&] {
        const TreeGroupState parsed = TreeWire::toRuntime(wireTree, 1, build.grantKey.getPublicKey());
        return parsed.nodes.size() == wireTree.nodes.size() ? std::string() : std::string("node count mismatch");
    });

    section("granting a container access to the group");
    std::string threadKeyWrap;
    measure("grant thread to group: wrap CK to the group", "ONE wrap, independent of group size", [&] {
        threadKeyWrap = privmx::crypto::EciesEncryptor::encryptToBase64(
            build.grantKey.getPublicKey(), containerKey, members[0].priv
        );
        return std::string();
    });
    measure("grant thread, FLAT baseline: wrap CK per member", "N wraps — and N again on every membership change", [&] {
        for (const TreeMember& member : roster) {
            privmx::crypto::EciesEncryptor::encryptToBase64(member.publicKey(), containerKey, members[0].priv);
        }
        return std::string();
    });

    // ── reading current content ──────────────────────────────────────────────
    section("reading current content");
    measure("read current message: WARM client (cached grant key)", "optimistic: nothing to do, the key is held", [&] {
        TreeKeys tree(ownerStore);
        const ClimbResult climb = tree.climbToGrantKey(state, members[0].userId, members[0].priv);
        return climb.grantKey.has_value() ? std::string() : "climb produced no key";
    });

    TreeKeyStore coldStore;
    measure("read current message: COLD client (must climb)", "pessimistic: depth unwraps, then symmetric decrypt", [&] {
        TreeKeys tree(coldStore);
        const ClimbResult climb = tree.climbToGrantKey(state, members[0].userId, members[0].priv, false);
        if (!climb.grantKey.has_value()) {
            return std::string("climb produced no key");
        }
        privmx::crypto::EciesEncryptor::decryptFromBase64(climb.grantKey.value(), threadKeyWrap);
        return std::string();
    });

    // ── removal ─────────────────────────────────────────────────────────────
    // The remover is member 0 and has already climbed, so its own path is cached: the optimistic case. The member
    // being removed sits at the far end of the tree, which is the *worst* position for cache reuse.
    // Everything that is not the operation itself is prepared first. `setMemberKeys` copies the roster, and
    // copying an EC public key is around a millisecond, so at this scale leaving it inside a timed block would
    // bury the operation under seconds of setup noise.
    section("removing a member");
    const std::uint32_t victim = memberCount - 1;
    TreeKeys warmTree(ownerStore);
    warmTree.setMemberKeys(roster);
    RemovalPlan warmRemoval;
    measure("remove member: WARM manager", "optimistic: 2*depth+1 wraps + depth keypairs, no climb needed", [&] {
        warmRemoval = warmTree.planRemoval(state, members[victim].userId, members[0].priv);
        return std::string();
    });

    TreeKeyStore coldRemoverStore;
    TreeKeys coldTree(coldRemoverStore);
    coldTree.setMemberKeys(roster);
    measure("remove member: COLD manager", "pessimistic: the same, preceded by a full climb from its own leaf", [&] {
        coldTree.climbToGrantKey(state, members[0].userId, members[0].priv, false);
        coldTree.planRemoval(state, members[memberCount - 2].userId, members[0].priv);
        return std::string();
    });

    measure("remove member: ladder rungs for the new epoch", "1 mandatory unit rung + O(log epoch) skip rungs", [&] {
        LadderKeys ladder(ownerStore);
        ladder.buildRungs(2, warmRemoval.newGrantKey.getPublicKey(), build.grantKey, 1, "u0", members[0].priv);
        return std::string();
    });

    measure("remove member: re-wrap the group's metadata key", "ONE wrap, addressed to the group itself", [&] {
        privmx::crypto::EciesEncryptor::encryptToBase64(
            warmRemoval.newGrantKey.getPublicKey(), containerKey, members[0].priv
        );
        return std::string();
    });

    measure("remove member, FLAT baseline", "new group key to N-1 members, then the container key again", [&] {
        const PrivateKey replacement = PrivateKey::generateRandom();
        for (std::uint32_t i = 0; i < memberCount; ++i) {
            if (i == victim) {
                continue;
            }
            TreeKeys::wrapKey(replacement, roster[i].publicKey(), members[0].priv);
            privmx::crypto::EciesEncryptor::encryptToBase64(roster[i].publicKey(), containerKey, members[0].priv);
        }
        return std::string();
    });

    // ── adding ──────────────────────────────────────────────────────────────
    // Apply the removal first, so there is a blank to seat somebody in — which is the case a real group is in most
    // of the time, and the cheap one.
    server::GroupTreeState afterRemoval = TreeWire::afterRemoval(wireTree, warmRemoval, victim);
    for (const NodeRefresh& refresh : warmRemoval.pathRefresh) {
        ownerStore.putNodeKey(refresh.nodeIndex, refresh.newGeneration, refresh.newKey);
    }
    ownerStore.putGrantKey(warmRemoval.newEpoch, warmRemoval.newGrantKey);
    const TreeGroupState stateAfterRemoval =
        TreeWire::toRuntime(afterRemoval, warmRemoval.newEpoch, warmRemoval.newGrantKey.getPublicKey());

    section("adding a member");
    const Member newcomer{"newcomer", PrivateKey::generateRandom()};
    const TreeMember newcomerPublic{newcomer.userId, newcomer.priv.getPublicKey()};
    std::vector<TreeMember> withNewcomer = roster;
    withNewcomer.push_back(newcomerPublic);
    TreeKeys addTree(ownerStore);
    addTree.setMemberKeys(withNewcomer);
    measure("add member into a blank", "one wrap; the epoch does NOT move, so no container re-keys", [&] {
        addTree.planAddition(stateAfterRemoval, newcomerPublic, members[0].priv);
        return std::string();
    });

    measure("add member, FLAT baseline", "one wrap too — addition was never the expensive direction", [&] {
        TreeKeys::wrapKey(warmRemoval.newGrantKey, newcomer.priv.getPublicKey(), members[0].priv);
        return std::string();
    });

    // Appending to a tree whose leaf count is already a power of two adds a level: a new root is minted above the
    // old one and the grant edge is re-linked to it. Measured on the pristine state, where every seat is taken.
    TreeKeys appendTree(ownerStore);
    appendTree.setMemberKeys(withNewcomer);
    measure(
        "add member: append to a FULL 2^k tree (new root)",
        "the tree grows a level; the epoch still does not move",
        [&] {
            const AdditionPlan plan = appendTree.planAddition(state, newcomerPublic, members[0].priv);
            if (plan.newNumLeaves != memberCount + 1) {
                return std::string("expected an append, got position ") + std::to_string(plan.position);
            }
            return std::string();
        }
    );

    // The awkward growth case: when the leaf count is not a power of two, appending re-parents an existing leaf,
    // so that member's edge has to be created too. Measured at two sizes to show the shape is logarithmic; the
    // cost is bounded by the wraps on one path, never by the group size.
    for (const std::uint32_t base : {255u, 1023u}) {
        if (base + 1 > memberCount) {
            continue;
        }
        const std::vector<TreeMember> smallRoster(roster.begin(), roster.begin() + base);
        TreeKeyStore smallStore;
        TreeKeys smallBuilder(smallStore);
        const BuildPlan smallBuild = smallBuilder.build(smallRoster, members[0].priv);
        // `build` does not populate the store — only a climb does — so the node keys are loaded by hand here,
        // which is what a member who had already climbed would hold.
        for (const auto& [nodeIndex, key] : smallBuild.nodeKeys) {
            smallStore.putNodeKey(nodeIndex, 0, key);
        }
        smallStore.putGrantKey(1, smallBuild.grantKey);
        const server::GroupTreeState smallWire = TreeWire::fromBuildPlan(smallBuild, smallRoster);
        const TreeGroupState smallState =
            TreeWire::toRuntime(smallWire, 1, smallBuild.grantKey.getPublicKey());

        std::vector<TreeMember> smallWithNewcomer = smallRoster;
        smallWithNewcomer.push_back(newcomerPublic);
        TreeKeys smallTree(smallStore);
        smallTree.setMemberKeys(smallWithNewcomer);
        std::ostringstream label;
        label << "add member: append re-parenting a leaf (N=" << base << " -> " << base + 1 << ", depth "
              << TreeMath::depth(base + 1) << ")";
        measure(label.str(), "worst growth shape: wraps along one path, bounded by 2*depth", [&] {
            smallTree.planAddition(smallState, newcomerPublic, members[0].priv);
            return std::string();
        });
    }

    // ── history: the Epoch Ladder ───────────────────────────────────────────
    // Build two ladders over the same epoch range: one as the implementation does it (with skip rungs), one
    // without, which is the pessimistic shape where a descent must pass through every intermediate epoch.
    std::cout << "\nBuilding " << withThousands(epochCount) << " epochs of ladder (twice: with and without skip rungs)...\n"
              << std::flush;

    struct Ladder {
        TreeKeyStore store;
        std::vector<ArchiveRung> rungs;
        std::vector<EpochRegistryEntry> registry;
        PrivateKey top;
    };

    const auto buildLadder = [&](bool includeSkipRungs) {
        auto ladder = std::make_shared<Ladder>();
        PrivateKey previous = PrivateKey::generateRandom();
        ladder->store.putGrantKey(1, previous);
        ladder->registry.push_back(EpochRegistryEntry{1, previous.getPublicKey()});
        LadderKeys keys(ladder->store);
        for (std::uint32_t epoch = 2; epoch <= epochCount; ++epoch) {
            const PrivateKey next = PrivateKey::generateRandom();
            const std::vector<ArchiveRung> produced = keys.buildRungs(
                epoch, next.getPublicKey(), previous, 1, "u0", members[0].priv, includeSkipRungs
            );
            ladder->rungs.insert(ladder->rungs.end(), produced.begin(), produced.end());
            ladder->registry.push_back(EpochRegistryEntry{epoch, next.getPublicKey()});
            ladder->store.putGrantKey(epoch, next);
            previous = next;
        }
        ladder->top = previous;
        return ladder;
    };

    const auto withSkips = buildLadder(true);
    const auto unitOnly = buildLadder(false);
    std::cout << "  rungs stored: " << withThousands(withSkips->rungs.size()) << " with skips, "
              << withThousands(unitOnly->rungs.size()) << " unit-only\n\n"
              << std::flush;

    section("reading history (Epoch Ladder)");
    for (const std::uint32_t age : {1u, 8u, 64u, 512u, epochCount - 1}) {
        if (age >= epochCount) {
            continue;
        }
        const std::uint32_t target = epochCount - age;
        {
            std::ostringstream label;
            label << "read message " << withThousands(age) << " epochs old: with skip rungs";
            measure(label.str(), "optimistic: ~log2(age) hops, each verified against the registry", [&] {
                TreeKeyStore cold;
                LadderKeys ladder(cold);
                cold.putGrantKey(epochCount, withSkips->top);
                const DescentResult descent =
                    ladder.descend(epochCount, target, withSkips->rungs, withSkips->registry, 1, std::nullopt);
                return descentStatus(descent);
            });
        }
        {
            std::ostringstream label;
            label << "read message " << withThousands(age) << " epochs old: unit rungs only";
            measure(label.str(), "pessimistic: one hop per epoch, no shortcuts available", [&] {
                TreeKeyStore cold;
                LadderKeys ladder(cold);
                cold.putGrantKey(epochCount, unitOnly->top);
                const DescentResult descent =
                    ladder.descend(epochCount, target, unitOnly->rungs, unitOnly->registry, 1, std::nullopt);
                return descentStatus(descent);
            });
        }
    }

    // ── sending ─────────────────────────────────────────────────────────────
    section("sending content");
    measure("send message (key already held)", "symmetric only: group size and history are irrelevant", [&] {
        privmx::crypto::Crypto::aes256CbcPkcs7Encrypt(
            std::string(512, 'x'), containerKey, privmx::crypto::Crypto::randomBytes(16)
        );
        return std::string();
    });

    // ── signatures ──────────────────────────────────────────────────────────
    // Worth its own section because of what the counts above show: the tree and the ladder perform **no** ECDSA
    // at all. Every edge and rung is an ECIES blob whose authenticity comes from the static ECDH — only a holder
    // of the recipient key can open it, and only the named author could have produced that shared secret.
    //
    // Signatures live one layer up, in the group's integrity chain: each `data` entry carries a signed DIO and a
    // signed membership block, verified on every read. That check is linear in the number of history entries,
    // which is the one place where a signature cost grows with anything.
    section("signatures (integrity chain, not the key tree)");
    const std::string dioLike = std::string(256, 'd');
    std::string dioSignature;
    measure("sign one history entry (DIO + membership)", "what a manager pays per group mutation", [&] {
        dioSignature = members[0].priv.signToCompactSignature(dioLike);
        privmx::crypto::Crypto::sha256(dioLike); // chain link over the previous entry
        return std::string();
    });

    const PublicKey authorPub = members[0].priv.getPublicKey();
    measure("verify one history entry", "what every reader pays per entry, on every read", [&] {
        return authorPub.verifyCompactSignature(dioLike, dioSignature) ? std::string()
                                                                      : std::string("signature did not verify");
    });

    for (const std::uint32_t entries : {1u, 16u, 256u}) {
        std::ostringstream label;
        label << "verify a chain of " << entries << " history entries";
        measure(label.str(), "assertDataIntegrity is linear in history length", [&] {
            for (std::uint32_t i = 0; i < entries; ++i) {
                if (!authorPub.verifyCompactSignature(dioLike, dioSignature)) {
                    return std::string("signature did not verify");
                }
                privmx::crypto::Crypto::sha256(dioLike);
            }
            return std::string();
        });
    }

    printDetailedTable();
    printCalibration(200, roster);

    // ── process totals, per class ───────────────────────────────────────────
    const auto totals = CryptoOpStats::read();
    std::cout << "\n" << std::string(46, '=') << " PROCESS TOTALS " << std::string(39, '=') << "\n\n";
    std::cout << std::left << std::setw(24) << "class / primitive" << std::right << std::setw(16) << "count" << "\n";
    std::cout << std::string(40, '-') << "\n";
    std::cout << std::left << std::setw(24) << "ASYMMETRIC" << std::right << std::setw(16)
              << withThousands(totals.asymmetric()) << "\n";
    for (std::size_t i = 0; i < CryptoOpStats::OpCount; ++i) {
        const auto op = static_cast<CryptoOpStats::Op>(i);
        if (CryptoOpStats::isAsymmetric(op) && totals.get(op) > 0) {
            std::cout << std::left << std::setw(24) << (std::string("  ") + CryptoOpStats::name(op)) << std::right
                      << std::setw(16) << withThousands(totals.get(op)) << "\n";
        }
    }
    std::cout << std::left << std::setw(24) << "symmetric" << std::right << std::setw(16)
              << withThousands(totals.symmetric()) << "\n";
    for (std::size_t i = 0; i < CryptoOpStats::OpCount; ++i) {
        const auto op = static_cast<CryptoOpStats::Op>(i);
        if (!CryptoOpStats::isAsymmetric(op) && op != CryptoOpStats::Op::RandomBytes && totals.get(op) > 0) {
            std::cout << std::left << std::setw(24) << (std::string("  ") + CryptoOpStats::name(op)) << std::right
                      << std::setw(16) << withThousands(totals.get(op)) << "\n";
        }
    }
    std::cout << std::left << std::setw(24) << "randomness" << std::right << std::setw(16)
              << withThousands(totals.get(CryptoOpStats::Op::RandomBytes)) << "\n";
    std::cout << std::string(40, '-') << "\n";
    std::cout << std::left << std::setw(24) << "TOTAL" << std::right << std::setw(16) << withThousands(totals.total())
              << "\n";

    std::cout << "\nReading the table: one ECIES wrap decomposes into 1 ECDH + 1 SHA-512 + 1 AES-enc + 2 HMAC,\n"
                 "an unwrap into 1 ECDH + 1 SHA-512 + 1 AES-dec + 1 HMAC. Note that the key tree and the ladder\n"
                 "perform NO sign and NO verify at all — authenticity there comes from the static ECDH, since only\n"
                 "the named author could derive the shared secret. Signatures belong to the integrity chain, whose\n"
                 "verify cost is linear in the number of history entries.\n";
    return 0;
}
