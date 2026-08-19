/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEKEYCACHEREGISTRY_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEKEYCACHEREGISTRY_HPP_

#include <map>
#include <memory>
#include <shared_mutex>
#include <string>

#include "privmx/endpoint/group/keytree/TreeKeyCache.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

/**
 * The per-group stores for one connection.
 *
 * Scoping lives here rather than inside `TreeKeyCache` so that `TreeKeys`, `LadderKeys` and `GroupKeyResolver` —
 * none of which has any use for a group id — keep working on a plain store. The id is known at the `GroupApiImpl`
 * boundary and nowhere deeper, which is exactly where this sits.
 *
 * Invalidation **detaches** a store instead of emptying it. That is what makes it safe to drop a group's keys
 * while another thread is mid-climb: the climber holds a `shared_ptr` and keeps writing into what is now a
 * private orphan, which dies with the operation. Emptying a shared store would instead let an in-flight climb
 * write stale keys back in after the drop.
 */
class TreeKeyCacheRegistry {
public:
    /**
     * The store for one group, created on first use. Never null.
     *
     * **Bind the result to a named local** before taking a reference into it. `TreeKeys tree(*registry.get(id))`
     * leaves `tree` holding a reference into a store whose last owner died at the end of the full expression.
     */
    std::shared_ptr<TreeKeyCache> get(const std::string& groupId);

    /** Detaches one group's store. Handles already taken stay valid; they just stop being shared. */
    void drop(const std::string& groupId);

    /** Detaches every store. */
    void dropAll();

    /** Number of groups with a live store. For tests and diagnostics. */
    std::size_t groupCount() const;

private:
    mutable std::shared_mutex _mutex;
    std::map<std::string, std::shared_ptr<TreeKeyCache>> _stores;
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEKEYCACHEREGISTRY_HPP_
