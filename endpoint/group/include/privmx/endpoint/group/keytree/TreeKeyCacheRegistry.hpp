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

// The per-group stores for one connection. Invalidation detaches a store instead of emptying it, so a climb
// already in flight keeps writing into a private orphan rather than putting stale keys back into a live store.
class TreeKeyCacheRegistry {
public:
    // Created on first use, never null. Bind the result to a named local before taking a reference into it —
    // `TreeKeys tree(*registry.get(id))` references a store whose last owner dies at the end of the expression.
    std::shared_ptr<TreeKeyCache> get(const std::string& groupId);

    // Handles already taken stay valid; they just stop being shared.
    void drop(const std::string& groupId);

    void dropAll();

    // For tests and diagnostics.
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
