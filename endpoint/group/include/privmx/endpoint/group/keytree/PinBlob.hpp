/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_PINBLOB_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_PINBLOB_HPP_

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include <privmx/endpoint/core/LocalSeal.hpp>

#include "privmx/endpoint/group/keytree/TreeVerifier.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

// The body of the `group-pins` slot (sealed by core `sealLocal`), and the rule two instances of one device merge
// their pins by (`higher`). Integers big-endian, lp = u32 length || bytes:
//
//   body   = u32 count || record*count                                   (sorted by groupId, no duplicates)
//   record = lp(groupId) || lp(contextId) || u64 seq || lp(digest) || u64 date
//          || u64 keyVersion || lp(groupPubKey) || u64 rosterVersion || lp(rosterHash)
//          || lp(creator) || lp(update) || lp(rotateKeys) || lp(updatePolicy) || lp(ownerCanBeRemovedFromManagers)
//          || lp(rulesHash) || lp(treeHash) || u64 refusedSeq || u64 seenAt
//          || u64 planeRosterVersion || u64 planePublicMetaVersion || u64 planePrivateMetaVersion
//          || u8 flags        bit0 roster present, bit1 nodes present (requires bit0), others 0
//          || [u32 nUsers || lp(user)* || u32 nManagers || lp(manager)*]          if bit0
//          || [u32 nNodes || (u32 nodeIndex || u32 generation)*]                   if bit1
//
// A compact record (bits 0 and 1 clear) keeps every scalar and drops roster and generations. A seq-0 record carries
// only refusedSeq and the plane counters.
class PinBlob {
public:
    static constexpr std::uint8_t VERSION = core::localstate::GROUP_PINS_VERSION;
    static constexpr const char* LABEL = core::localstate::GROUP_PINS_LABEL;
    // Limit: full rosters up to 1 MiB, the rest compact (one genesis replay each); per-group slots if it bites.
    static constexpr std::size_t BUDGET = 1 << 20;

    // Two passes, no record ever dropped: every group compact, then by seenAt descending upgraded to full while the
    // body stays within BUDGET (above it, compact records are still all written).
    static std::string encode(const TreeVerifier::PinSet& pins);
    // Strict: nullopt on a length past the end, trailing bytes, unknown flag bits, bit1 without bit0, unsorted or
    // duplicate group ids.
    static std::optional<TreeVerifier::PinSet> decode(const std::string& body);
    // Two records of one group, both verified on this device: the higher seq wins; at one seq `mine` stays (with
    // `other`'s roster and generations folded in at the same digest). A seq-0 side counts as absent. `refusedSeq` and
    // `seenAt` by max; generations by max when `other` wins. Two branches at one seq are not reconciled: the device
    // keeps whichever it holds, as a bridge able to fork could as well withhold.
    static TreeVerifier::Pin higher(const TreeVerifier::Pin* mine, const TreeVerifier::Pin* other);
    // `higher` for every group, planes by max: what a save writes.
    static TreeVerifier::PinSet mergeForSave(const TreeVerifier::PinSet& mine, const TreeVerifier::PinSet& stored);
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_PINBLOB_HPP_
