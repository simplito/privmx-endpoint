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

enum class RungRecipientKind {
    // The group's own grant public key at `span.at` — an ordinary chain or skip rung.
    Epoch,
    // A single member — used only to cross an era boundary.
    User,
    // An entitlement group — the O(1) way to cross an era boundary.
    Group,
};

// A published rung: `wrap(sk_{span.target} -> pk_recipient)`. For `Epoch` the recipient is the group's own grant
// key, which is what makes the ladder cost size-independent: one ciphertext serves every member, present and future.
struct ArchiveRung {
    RungSpan span{0, 0};
    RungRecipientKind recipientKind = RungRecipientKind::Epoch;
    std::string recipientId; // userId or groupId, for the two era-crossing kinds
    std::string blob;        // ECIES ciphertext, base64. Opaque to the server.
    std::string author;      // who published it — the handle for attributing detected tampering
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
    // Publisher of the offending rung, when `failure == Tampered`.
    std::optional<std::string> blame;
    // Rungs actually traversed, reported rather than inferred: a ladder carrying its skip rungs walks
    // `O(log delta)`, one that lost them walks `delta`.
    std::uint32_t hops = 0;
};

// An entitlement target for an era-crossing link: a member or a group, with the key to wrap to.
struct EraLinkRecipient {
    RungRecipientKind kind = RungRecipientKind::User;
    std::string id;
    privmx::crypto::PublicKey publicKey;
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_LADDERTYPES_HPP_
