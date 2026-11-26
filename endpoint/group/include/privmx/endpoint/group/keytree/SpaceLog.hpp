/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_SPACELOG_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_SPACELOG_HPP_

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>

#include "privmx/endpoint/group/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

// A Space's history: signed statements chained by digest, each carrying the full list of recipients after it.
// The Bridge stores them; what a Space is - who its recipients are, which key version is current, who made it -
// is what replaying them gives. Nothing here talks to a server or holds a key of the Space: the format, and the
// rules that say which statement may follow which. Format: proposals/space-log-format.md.

enum class SpaceOp : std::uint8_t {
    Create = 1,
    Add = 2,
    Remove = 3,
    Rotate = 4,
};

struct SpaceLogGroup {
    std::string groupId;
    std::string role;
    std::uint64_t groupKeyVersion = 0;
    std::string groupPubKey; // base58-DER
};

struct SpaceLogUser {
    std::string userId;
    std::string pubKey; // base58-DER
    std::string role;
};

struct SpaceStatement {
    std::string spaceId;
    std::string contextId;
    std::uint64_t seq = 0;
    std::string prevDigest; // raw: empty at seq 1, 32 bytes after
    SpaceOp op = SpaceOp::Create;
    std::uint64_t date = 0;
    std::uint64_t keyVersion = 0;
    std::string keyCommit; // raw, 32 bytes
    std::vector<SpaceLogGroup> groups;
    std::vector<SpaceLogUser> users;
    std::string signer;
    std::string signerPubKey; // base58-DER
    std::string via;          // empty: the signer is a recipient themselves; else the recipient group they act through
    std::string signature;    // raw
    std::string viaSignature; // raw; empty when `via` is
};

// What the statements up to `seq` add up to.
struct SpaceLogState {
    std::string spaceId;
    std::string contextId;
    std::string creator; // the signer of statement 1
    std::uint64_t seq = 0;
    std::string digest; // of statement `seq`, raw
    std::uint64_t keyVersion = 0;
    std::vector<SpaceLogGroup> groups;
    std::vector<SpaceLogUser> users;
    std::map<std::uint64_t, std::string> keyCommits; // by key version

    // "manager", "user", or "" for someone who is no recipient themselves.
    std::string roleOfUser(const std::string& userId) const;
    const SpaceLogGroup* group(const std::string& groupId) const;
};

class SpaceLog {
public:
    static std::string recipientsHash(std::vector<SpaceLogGroup> groups, std::vector<SpaceLogUser> users);
    static std::string keyCommit(const std::string& spaceId, std::uint64_t keyVersion, const std::string& key);
    // Throws std::invalid_argument for a statement no writer makes (a hash of the wrong size).
    static std::string signedBytes(const SpaceStatement& statement);
    static std::string viaBytes(const SpaceStatement& statement);
    static std::string digest(const SpaceStatement& statement);

    // Sets `signer`'s key and signature; with `viaKey`, the signature of the group the signer acts through.
    static void sign(
        SpaceStatement& statement,
        const privmx::crypto::PrivateKey& signerKey,
        const std::optional<privmx::crypto::PrivateKey>& viaKey
    );

    // The state after `statement`, which must be the one that may follow `prior` (std::nullopt: it is the first).
    // Checks everything the statement itself can show: the chain, both signatures, the signer's standing among
    // the recipients before it, and that the recipients and the key version moved only as its op allows.
    // A recipient group's pinned epoch and key move forward only, by a manager or through that group itself.
    // What it cannot check is that `signer` is who holds `signerPubKey`: that is the caller's to ask the UserVerifier.
    // Throws GroupDataIntegrityException or GroupUnauthorizedSignerException.
    static SpaceLogState apply(const std::optional<SpaceLogState>& prior, const SpaceStatement& statement);

    static server::SpaceStatement toWire(const SpaceStatement& statement);
    static SpaceStatement fromWire(const server::SpaceStatement& wire);
    static std::string opName(SpaceOp op);
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_SPACELOG_HPP_
