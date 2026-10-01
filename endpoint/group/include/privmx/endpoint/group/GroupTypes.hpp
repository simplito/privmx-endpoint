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
#include <string>
#include <vector>

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/group/Types.hpp"

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
    ChunkIndex index = 0;       // next chunk to seal or open
    ByteCount plainSize = 0;    // declared plaintext length of the whole file
    ByteCount written = 0;      // write side: plaintext accepted so far
    ByteCount skipInChunk = 0;  // read side: bytes to drop off the next chunk after a seek
    bool seeked = false;        // read side: completeness is no longer checkable
    std::string buffer{};       // bytes not yet forming a whole chunk
};

// A roster split the way `prepareContainerUpdate` wants it.
struct RosterAfterChange {
    std::vector<core::UserWithPubKey> users;
    std::vector<core::UserWithPubKey> managers;
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
