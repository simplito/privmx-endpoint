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
#include <functional>
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

// What an envelope carries. Part of the signed (or sealed) header, so one kind is never opened as another: a
// file's manifest would hand back the file key as if it were message content.
enum class EnvelopeContent : std::uint8_t {
    Message = 0,
    File = 1,     // content is a file manifest: the file key and a digest of every chunk
    Sequence = 2, // content is the key of a sequence; items and marks follow outside the envelope
    // A Space's private metadata. A kind of its own, which no location of the application's reaches: a recipient
    // cannot write a value that reads as the Space's metadata.
    SpaceMeta = 3,
};

// What an envelope is bound to, beside its group: a location in the application's data, or - said, never
// defaulted - none. Not transmitted: the writer signs it, the reader supplies it again and the two must agree.
struct EnvelopeBinding {
    bool hasLocation = false;
    std::string locationDigest{}; // 32 bytes when `hasLocation`, empty otherwise
    EnvelopeContent content = EnvelopeContent::Message;
};

// What a writer stamps into the signed part of an envelope.
struct EnvelopeSeal {
    EnvelopeBinding binding{};
    std::int64_t keyVersion = 0;  // member envelopes: the epoch of the group key used
    std::int64_t encryptedAt = 0; // signed envelopes: the writer's clock, ms
    // Signed envelopes: who the writer says they are. A claim like the public key beside it: the caller has the
    // UserVerifier confirm that this user holds that key before showing either.
    std::string authorUserId{};
};

// One more reader of an envelope, beside the group it is written in. Part of the signed header.
struct WireRecipient {
    bool isGroup = false;
    std::string id{};            // group id or user id
    std::string pubKey{};        // base58-DER: the key the content key is wrapped to
    std::int64_t keyVersion = 0; // groups: the epoch of `pubKey`; 0 for a user
};

// The plain header, read without opening anything. Nothing in it is authenticated until the envelope is opened.
struct EnvelopeRouting {
    EnvelopeType type;
    EnvelopeContent content = EnvelopeContent::Message;
    bool hasLocation = false;
    std::string groupId;         // for an envelope in a Space: the group the author wrote through, or empty
    std::string spaceId;         // envelopes in a Space only
    std::string keyId;           // member envelopes only
    std::int64_t keyVersion = 0; // member envelopes: the epoch the writer claims; in a Space: the Space key's version
    std::string groupPubKey;     // base58-DER; outsider and anonymous envelopes only
    std::string authorUserId;    // signed envelopes only
    std::string authorPubKey;    // base58-DER; signed envelopes only
    std::vector<WireRecipient> recipients; // signed message envelopes only
};

// A message envelope, opened. `authorPubKey` is empty for ENVELOPE_ANONYMOUS.
struct OpenedEnvelope {
    core::Buffer data;
    std::string groupId;
    std::string keyId;
    std::int64_t keyVersion = 0;
    std::string authorUserId;
    std::string authorPubKey;
    std::int64_t encryptedAt = 0;
    std::vector<WireRecipient> recipients;
    EnvelopeType type;
    // true when it was opened as a further recipient (`openSharedEnvelope`). The reader then never held the home
    // group's key, so `groupId`, `keyId`, `keyVersion` and `type` are what the writer signed and nothing more:
    // anyone in the context can write "from a member of group G" to a recipient. Whether the writer is a member
    // of `groupId` is for the caller to establish against that group's roster, or to report as unknown.
    bool homeGroupUnverified = false;
};

// One chunk of a file, as the file's envelope lists it.
struct FileChunk {
    std::uint32_t plainSize = 0;
    std::string digest{}; // sha256 of the chunk's ciphertext
};

struct EnvelopeFileState {
    bool reading = false;
    std::string fileKey{};
    // Writing: the chunks sealed so far. Reading: the chunks the envelope lists.
    std::vector<FileChunk> chunks{};
    ChunkIndex index = 0;      // read side: next chunk to open
    ByteCount skipInChunk = 0; // read side: bytes to drop off the next chunk after a seek
    bool seeked = false;       // read side: completeness is no longer checkable
    std::string buffer{};      // read side: ciphertext not yet forming a whole chunk
    bool closed = false;       // set by the finish, under the handle's lock; later calls are refused
    // Write side: makes the envelope out of the manifest, at the finish. Which kind of envelope (a member's,
    // an outsider's, an anonymous one, one in a Space) is decided when the file is begun and lives here.
    std::function<core::Buffer(const core::Buffer& manifest)> seal{};
    // Read side: what opening the envelope established, handed back at the finish.
    DecryptedFileInfo info{};
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
