/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_LADDERTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_LADDERTYPES_HPP_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>

#include "privmx/endpoint/group/keytree/LadderMath.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

// A published rung: `wrap(sk_{span.target} -> pk_{span.at})`, sealed to the group's own grant key at `span.at`,
// which is what makes the ladder cost size-independent: one ciphertext serves every member, present and future.
// There is no other kind of recipient: a rung sealed to anything else would satisfy the unit-rung rule while
// leaving the epoch unreachable from below.
struct ArchiveRung {
    RungSpan span{0, 0};
    std::string blob;   // ECIES ciphertext, base64. Opaque to the server.
    // Who to blame for detected tampering. `GroupKeyResolver::authenticated` sets it to the opener of `span.at` (from
    // the signed statement) for a rung sealed under that opener's key and clears it for any other sealer, so the
    // bridge alone cannot name a culprit. It is no proof of authorship: the seal is static ECDH, and anyone holding
    // `sk_{span.at}` (every member of that epoch) can seal a rung under the opener's key and have it blamed on them.
    std::string author;
};

// The anchor of verification: a party derives the public key from whatever it recovers and compares against this,
// so it can check a rung published long before it joined. That is what makes a rung deniable but not forgeable.
struct EpochRegistryEntry {
    std::uint32_t epoch = 0;
    privmx::crypto::PublicKey grantPublicKey;
};

// The distinctions are part of the contract with the UI layer.
enum class DescentFailure {
    None,
    // Reached an era floor. Normal policy — an entitlement matter, not an error.
    EraBoundary,
    // Reached a prune watermark. Normal retention policy.
    Pruned,
    // The chain is broken: no rung leads on from an epoch we reached.
    MissingRung,
    // A rung did not open with the key we hold.
    DecryptFailed,
    // A recovered key does not match the registry. A security event: deterministic and adversarial, never retry.
    Tampered,
    // The walk exceeded its bound; a pathological or hostile rung set.
    TooLong,
    // The caller holds no key to start from.
    NotEntitled,
};

struct DescentResult {
    std::optional<privmx::crypto::PrivateKey> key;
    DescentFailure failure = DescentFailure::None;
    // Oldest epoch actually recovered. Partial progress is cached and worth reporting.
    std::uint32_t reachedEpoch = 0;
    // Publisher of the offending rung, when `failure == Tampered`: the first rung at the failing hop that carries an
    // author (opener-sealed) and opens to a wrong key, whichever candidate failed first. An unattributed rung (sealed
    // by anybody else, e.g. a repair) never sets it, and cannot mask the opener's bad rung either.
    std::optional<std::string> blame;
    // Rungs actually traversed, reported rather than inferred: a ladder carrying its skip rungs walks
    // `O(log delta)`, one that lost them walks `delta`.
    std::uint32_t hops = 0;
    // Spans the walk found broken: at a hop, every rung of a span with a lower target than the one taken (or, when
    // nothing opened, of every candidate span) failed. A holder of both keys can repair them (`groupRepairRung`).
    std::vector<RungSpan> brokenSpans;
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_LADDERTYPES_HPP_
