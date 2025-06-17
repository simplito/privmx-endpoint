/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_USERS_KEYS_RESOLVER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_USERS_KEYS_RESOLVER_HPP_

#include <algorithm>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <privmx/utils/TypedObject.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/Utils.hpp>

namespace privmx {
namespace endpoint {
namespace core {

class UsersKeysResolver {
public:
    UsersKeysResolver(
            const std::vector<core::UserWithPubKey>& users,
            const std::vector<core::UserWithPubKey>& managers
    );

private:
    std::vector<core::UserWithPubKey> _users;
    std::vector<core::UserWithPubKey> _managers;
    
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_USERS_KEYS_RESOLVER_HPP_