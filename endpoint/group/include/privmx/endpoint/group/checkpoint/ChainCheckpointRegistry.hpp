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

/**
 * The per-group checkpoints for one connection.
 *
 * Scoping lives here rather than inside `ChainCheckpoint` for the same reason as `TreeKeyCacheRegistry`: the id
 * is known at the schema-mapper boundary and nowhere deeper, and nothing inside a single checkpoint is keyed by
 * group.
 *
 * Invalidation **detaches** a store instead of clearing it, so it's safe to drop a group's checkpoint while
 * another thread is mid-verification of it: the verifier holds a `shared_ptr` and finishes writing into what is
 * now a private orphan, which dies with the call. Clearing a shared store in place could instead let an
 * in-flight verification write a stale-but-still-monotonic snapshot back in right after the drop.
 */
class ChainCheckpointRegistry {
public:
    /** The checkpoint for one group, created on first use. Never null. */
    std::shared_ptr<ChainCheckpoint> get(const std::string& groupId);

    /** The checkpoint for one group if it already exists, without creating one. For tests and diagnostics. */
    std::shared_ptr<ChainCheckpoint> tryGet(const std::string& groupId) const;

    /** Detaches one group's checkpoint. Handles already taken stay valid; they just stop being shared. */
    void drop(const std::string& groupId);

    /** Detaches every checkpoint. */
    void dropAll();

    /** Number of groups with a live checkpoint. For tests and diagnostics. */
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
