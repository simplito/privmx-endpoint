/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/checkpoint/ChainCheckpoint.hpp"

#include <mutex>
#include <shared_mutex>

using namespace privmx::endpoint::group::checkpoint;

std::optional<ChainCheckpoint::Snapshot> ChainCheckpoint::get() const {
    std::shared_lock lock(_mutex);
    return _snapshot;
}

void ChainCheckpoint::advance(const Snapshot& candidate) {
    std::unique_lock lock(_mutex);
    if (_snapshot.has_value() && candidate.verifiedVersion <= _snapshot->verifiedVersion) {
        return;
    }
    _snapshot = candidate;
}
