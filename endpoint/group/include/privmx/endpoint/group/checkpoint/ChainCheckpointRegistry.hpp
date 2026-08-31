/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_CHECKPOINT_CHAINCHECKPOINTREGISTRY_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_CHECKPOINT_CHAINCHECKPOINTREGISTRY_HPP_

#include <map>
#include <memory>
#include <shared_mutex>
#include <string>

#include "privmx/endpoint/group/checkpoint/ChainCheckpoint.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace checkpoint {

// The per-group checkpoints for one connection. Like `TreeKeyCacheRegistry`, invalidation detaches a store rather
// than clearing it, so a verification in flight finishes into a private orphan instead of writing a stale snapshot.
class ChainCheckpointRegistry {
public:
    // Created on first use, never null.
    std::shared_ptr<ChainCheckpoint> get(const std::string& groupId);

    // Without creating one. For tests and diagnostics.
    std::shared_ptr<ChainCheckpoint> tryGet(const std::string& groupId) const;

    // Handles already taken stay valid; they just stop being shared.
    void drop(const std::string& groupId);

    void dropAll();

    // For tests and diagnostics.
    std::size_t groupCount() const;

private:
    mutable std::shared_mutex _mutex;
    std::map<std::string, std::shared_ptr<ChainCheckpoint>> _stores;
};

} // namespace checkpoint
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_CHECKPOINT_CHAINCHECKPOINTREGISTRY_HPP_
