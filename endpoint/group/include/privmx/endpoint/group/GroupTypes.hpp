/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPTYPES_HPP_

#include <cstdint>
#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <Poco/Dynamic/Var.h>
#include <privmx/crypto/ecc/PrivateKey.hpp>

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/group/Types.hpp"
#include "privmx/endpoint/group/keytree/TreeKeyCache.hpp"

namespace privmx {
namespace endpoint {
namespace group {

// Deliberately 32-bit: the wire writes it as `u32be` into the chunk key, so the width is a format constraint.
using ChunkIndex = std::uint32_t;
// A count of bytes, or of chunks.
using ByteCount = std::uint64_t;

// The file header a file envelope carries, once opened. Produced by `GroupEnvelopeEncryptor::unpackFileEnvelope`
// and `unpackAnonymousFileEnvelope`.
struct EnvelopeFileHeader {
    EnvelopeType type;
    std::string groupId;
    std::string keyId;        // set for ENVELOPE_FROM_MEMBER only
    std::string authorPubKey; // base58-DER, signature verified; EMPTY for ENVELOPE_ANONYMOUS
    ByteCount plainSize;
    std::string fileKey; // 32 raw bytes
};

// The routing header, read without opening anything.
struct EnvelopeRouting {
    EnvelopeType type;
    std::string groupId;
    std::string keyId;       // set for ENVELOPE_FROM_MEMBER only
    std::string groupPubKey; // base58-DER; set for ENVELOPE_ANONYMOUS only
};

struct EnvelopeFileState {
    bool reading = false;
    EnvelopeType type{};
    std::string groupId{};
    std::string keyId{};        // member files only
    std::string groupKey{};     // member files only
    std::string groupPubKey{};  // anonymous seals only, base58-DER
    std::string authorPubKey{}; // opening only: provenance handed back at finish
    std::string fileKey{};
    ChunkIndex index = 0;      // next chunk to seal or open
    ByteCount plainSize = 0;   // declared plaintext length of the whole file
    ByteCount written = 0;     // write side: plaintext accepted so far
    ByteCount skipInChunk = 0; // read side: bytes to drop off the next chunk after a seek
    bool seeked = false;       // read side: completeness is no longer checkable
    std::string buffer{};      // bytes not yet forming a whole chunk
    bool closed = false;       // set by the finish, under the handle's lock; later calls are refused
};

// One open file handle. Every call on the handle holds `mutex` for its whole duration, so calls on one
// handle never interleave; their order is still the caller's to choose.
struct EnvelopeFile {
    std::mutex mutex;
    EnvelopeFileState state; // guarded by mutex
};

// A roster split the way `prepareContainerUpdate` wants it.
struct RosterAfterChange {
    std::vector<core::UserWithPubKey> users;
    std::vector<core::UserWithPubKey> managers;

    // The attested roster, as bare ids — the update preparation diffs names, it does not wrap to them.
    static RosterAfterChange bare(const std::vector<std::string>& users, const std::vector<std::string>& managers) {
        const auto toBare = [](const std::vector<std::string>& ids) {
            std::vector<core::UserWithPubKey> out;
            out.reserve(ids.size());
            for (const std::string& id : ids) {
                out.push_back(core::UserWithPubKey{.userId = id, .pubKey = std::string()});
            }
            return out;
        };
        return RosterAfterChange{.users = toBare(users), .managers = toBare(managers)};
    }
};

// A plan whose base is behind the pin (the client's own commit, or a read, moved it meanwhile). Retryable: a fresh
// read plans on the newer head. Not an endpoint exception; `CommitEngine::commitWithRetry` and `DeferredWork::run`
// handle it.
struct StalePlan : std::exception {
    const char* what() const noexcept override { return "group commit planned behind the pinned state"; }
};

// Proceed: plan on the read. Done: the caller's own op landed (now or before). Reread: another op of this
// client, or an earlier call of an event op past its window, was completed first; read again. Deferred: a
// self-update yields to another op's commit.
enum class Settled {
    Proceed,
    Done,
    Reread,
    Deferred
};

// Which planes a carry-forward moves: after a removal or rotation, the planes behind the new epoch (or, with
// history abandoned, starts them over empty); after a narrowing policy commit, the planes whose author lost
// `update` (`losers`).
enum class CarryScope {
    NewEpoch,
    Policy
};

// What a commit opening a new epoch publishes beside the tree, shared by removal and rotation: the roster under a
// fresh metadata key (a key never used before once history is abandoned), and that key wrapped once to the new
// grant key.
struct NewEpochRoster {
    std::string keyId;
    Poco::Dynamic::Var data;
    core::server::GroupKeyEntrySet groupKeys;
};

// A climb with another key over another cache (leaf renewal); nothing then reaches the epoch keys, the group's
// shared cache or the due-work records.
struct ClimbWith {
    std::shared_ptr<keytree::TreeKeyCache> cache;
    const privmx::crypto::PrivateKey* key;
};

// The head, the resource id, the epoch, and a key proven to be the current epoch's.
struct MetaWriteContext {
    std::string resourceId;
    int64_t currentEpoch;
    core::ContainerUpdateContext ctx;
};

struct ResolvedGroupGrants {
    std::vector<core::server::GroupGrant> grants;
    std::vector<core::server::GroupKeyEntrySet> keyEntries;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPTYPES_HPP_
