/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_CHECKPOINT_CHAINCHECKPOINT_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_CHECKPOINT_CHAINCHECKPOINT_HPP_

#include <cstdint>
#include <optional>
#include <set>
#include <shared_mutex>
#include <string>

namespace privmx {
namespace endpoint {
namespace group {
namespace checkpoint {

// A trust-on-first-use anchor into one group's verified history, so a re-read only verifies the entries above the
// last verified one. A security anchor, not an optimisation — losing it is not free, and it only ever advances.
class ChainCheckpoint {
public:
    struct Snapshot {
        // Entries verified as of this checkpoint — equals `groupInfo.data.size()` at that time.
        int64_t verifiedVersion = 0;
        // hex(sha256(encData.dio)) of the checkpoint entry — the anchor every entry above it must chain into.
        std::string lastEntryDioHashHex;
        // membership.managers as committed by the checkpoint entry.
        std::set<std::string> verifiedManagers;
        // membership.users as committed by the checkpoint entry.
        std::set<std::string> verifiedUsers;
        // membership.keyVersion as committed there — needed to resume epoch monotonicity.
        int64_t keyVersionAtCheckpoint = 0;
        // membership.groupPubKey as committed there — needed to resume epoch monotonicity.
        std::string groupPubKeyAtCheckpoint;
    };

    // By value: a reference would outlive the lock.
    std::optional<Snapshot> get() const;

    // Stores `candidate` only if it reaches further than what is already stored, so a shorter but still validly
    // signed response — a rollback attempt — can never move the anchor backward.
    void advance(const Snapshot& candidate);

private:
    mutable std::shared_mutex _mutex;
    std::optional<Snapshot> _snapshot;
};

} // namespace checkpoint
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_CHECKPOINT_CHAINCHECKPOINT_HPP_
