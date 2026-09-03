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

// The highest version of one group this client has accepted.
//
// A trust-on-first-use pin, not an optimisation. The roster tag proves who a roster was attested by, but a tag
// stays valid forever — so an older, genuinely tagged roster is something only a version pin can refuse.
class ChainCheckpoint {
public:
    struct Snapshot {
        int64_t verifiedVersion = 0;
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
