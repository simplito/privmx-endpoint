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

// 01: the body of the `group-pins` slot (sealed by core `sealLocal`), and the rule two instances of one device merge
// their pins by. Integers big-endian, lp = u32 length || bytes:
//
//   body   = u32 count || record*count                                   (sorted by groupId, no duplicates)
//   record = lp(groupId) || lp(contextId) || u64 seq || lp(digest) || u64 date
//          || u64 keyVersion || lp(groupPubKey) || u64 rosterVersion || lp(rosterHash)
//          || lp(creator) || lp(update) || lp(rotateKeys) || lp(updatePolicy) || lp(ownerCanBeRemovedFromManagers)
//          || lp(rulesHash) || lp(treeHash) || u64 refusedSeq || u64 seenAt
//          || u64 planeRosterVersion || u64 planePublicMetaVersion || u64 planePrivateMetaVersion
//          || u8 flags        bit0 roster present, bit1 nodes present (requires bit0), bit2 forked, others 0
//          || [u32 nUsers || lp(user)* || u32 nManagers || lp(manager)*]          if bit0
//          || [u32 nNodes || (u32 nodeIndex || u32 generation)*]                   if bit1
//
// A compact record (bits 0 and 1 clear) keeps every scalar and drops roster and generations. A seq-0 record carries
// only refusedSeq and the plane counters.
class PinBlob {
public:
    static constexpr std::uint8_t VERSION = core::localstate::GROUP_PINS_VERSION;
    static constexpr const char* LABEL = core::localstate::GROUP_PINS_LABEL;
    // ponytail: full rosters up to 1 MiB, the rest compact (one genesis replay each); per-group slots if it bites.
    static constexpr std::size_t BUDGET = 1 << 20;

    // Per group, the merge of the pin in memory (M, as exported) with the stored record (R), S = M.synced:
    //   TakeMine   R absent; or R is what this instance last synced with (M moved since); or the slot went back (h2)
    //   TakeStored M absent; or M was never synced (a first contact here); or M is S and R moved past it
    //   Same       one state
    //   Fork       either forked, another context, or two digests at one seq: `forked` in the slot and in memory
    //   Pending    M waits for a link already: the slot keeps R
    //   Unlinked   both moved since S at different seqs: the slot keeps R, M is held until `TreeVerifier::link`
    // A seq-0 side counts as absent; refusedSeq, seenAt and the planes are merged by max whatever the case.
    enum class Case { TakeMine, TakeStored, Same, Fork, Pending, Unlinked };

    // Two passes, no record ever dropped: every group compact, then by seenAt descending upgraded to full while the
    // body stays within BUDGET (above it, compact records are still all written).
    static std::string encode(const TreeVerifier::PinSet& pins);
    // Strict: nullopt on a length past the end, trailing bytes, unknown flag bits, bit1 without bit0, unsorted or
    // duplicate group ids.
    static std::optional<TreeVerifier::PinSet> decode(const std::string& body);
    static Case decide(const TreeVerifier::Pin* mine, const TreeVerifier::Pin* stored);
    // The slot's side of `decide` for every group.
    static TreeVerifier::PinSet mergeForSave(const TreeVerifier::PinSet& mine, const TreeVerifier::PinSet& stored);
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_PINBLOB_HPP_
