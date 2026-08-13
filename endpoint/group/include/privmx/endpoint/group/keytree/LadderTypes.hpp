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

/** Who a rung is addressed to. */
enum class RungRecipientKind {
    /** The group's own grant public key at `span.at` — an ordinary chain or skip rung. */
    Epoch,
    /** A single member — used only to cross an era boundary. */
    User,
    /** An entitlement group — the O(1) way to cross an era boundary. */
    Group,
};

/**
 * A published rung: `wrap(sk_{span.target} -> pk_recipient)`.
 *
 * For `RungRecipientKind::Epoch` the recipient is the group's grant key at `span.at`, which is what makes the
 * ladder cost independent of group size: one ciphertext serves every member, present and future.
 */
struct ArchiveRung {
    RungSpan span{0, 0};
    RungRecipientKind recipientKind = RungRecipientKind::Epoch;
    std::string recipientId; ///< userId or groupId, for the two era-crossing kinds
    std::string blob;        ///< ECIES ciphertext, base64. Opaque to the server.
    std::string author;      ///< who published it — the handle for attributing detected tampering
};

/**
 * One entry of the authenticated epoch registry: epoch -> public grant key.
 *
 * This is the **anchor of verification**. A party that joined at epoch 40 cannot attest a rung published at
 * epoch 12 — it never held that key — but it does not need to: it derives the public key from whatever it
 * recovers and compares against this registry. That is what makes a rung deniable but not forgeable.
 */
struct EpochRegistryEntry {
    std::uint32_t epoch = 0;
    privmx::crypto::PublicKey grantPublicKey;
};

/** Why a descent failed. The distinctions are part of the contract with the UI layer. */
enum class DescentFailure {
    None,
    /** Reached an era floor. Normal policy — an entitlement matter, not an error. */
    EraBoundary,
    /** Reached a prune watermark. Normal retention policy. */
    Pruned,
    /** The chain is broken: no rung leads on from an epoch we reached. */
    MissingRung,
    /** A rung did not open with the key we hold. */
    DecryptFailed,
    /**
     * A recovered key does not match the registry.
     *
     * A **security event**. Deterministic and adversarial — never retry. `blame` names the publisher.
     */
    Tampered,
    /** The walk exceeded its bound; a pathological or hostile rung set. */
    TooLong,
    /** The caller holds no key to start from. */
    NotEntitled,
};

struct DescentResult {
    /** The grant private key for the requested epoch, on success. */
    std::optional<privmx::crypto::PrivateKey> key;
    DescentFailure failure = DescentFailure::None;
    /** Oldest epoch actually recovered. Partial progress is cached and worth reporting. */
    std::uint32_t reachedEpoch = 0;
    /** Publisher of the offending rung, when `failure == Tampered`. */
    std::optional<std::string> blame;
};

/** An entitlement target for an era-crossing link: a member or a group, with the key to wrap to. */
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
