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
#include <memory>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <privmx/utils/TypedObject.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/Utils.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>

namespace privmx {
namespace endpoint {
namespace core {

class UsersKeysResolver {
public:
    template<typename ModuleStructAsTypedObj>
    static auto create(
            ModuleStructAsTypedObj moduleObj,
            const std::vector<core::UserWithPubKey>& users,
            const std::vector<core::UserWithPubKey>& managers,
            const bool forceGenerateNewKey,
            const DecryptedEncKeyV2& moduleCurrentKey
    )-> decltype(moduleObj.users(), moduleObj.managers(), std::shared_ptr<UsersKeysResolver>());

    std::vector<core::UserWithPubKey> getUsersToAddKey();
    std::vector<core::UserWithPubKey> getNewUsers();
    bool doNeedNewKey();

private:
    template<typename ModuleStructAsTypedObj>
    auto init(
            ModuleStructAsTypedObj moduleObj,
            const std::vector<core::UserWithPubKey>& users,
            const std::vector<core::UserWithPubKey>& managers,
            const bool forceGenerateNewKey,
            const DecryptedEncKeyV2& moduleCurrentKey
    )-> decltype(moduleObj.users(), moduleObj.managers(), void());

    std::vector<core::UserWithPubKey> _usersToAddMissingKey;
    std::vector<core::UserWithPubKey> _new_users;

    bool _needNewKey;
};

template<typename ModuleStructAsTypedObj>
auto UsersKeysResolver::create(
        ModuleStructAsTypedObj moduleObj,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const bool forceGenerateNewKey,
        const DecryptedEncKeyV2& moduleCurrentKey
)-> decltype(moduleObj.users(), moduleObj.managers(), std::shared_ptr<UsersKeysResolver>()) {
    auto instance = std::make_shared<UsersKeysResolver>();
    instance->init(moduleObj, users, managers, forceGenerateNewKey, moduleCurrentKey);
    return instance;
}

template<typename ModuleStructAsTypedObj>
auto UsersKeysResolver::init(
    ModuleStructAsTypedObj moduleObj,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const bool forceGenerateNewKey,
    const DecryptedEncKeyV2& moduleCurrentKey
)-> decltype(moduleObj.users(), moduleObj.managers(), void()) {
    // extract current users info
    auto usersVec {core::EndpointUtils::listToVector<std::string>(moduleObj.users())};
    auto managersVec {core::EndpointUtils::listToVector<std::string>(moduleObj.managers())};
    auto oldUsersIds {core::EndpointUtils::uniqueList(usersVec, managersVec)};

    _new_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    auto newUsersIds {core::EndpointUtils::usersWithPubKeyToIds(_new_users)};
    auto deletedUsersIds {core::EndpointUtils::getDifference(oldUsersIds, newUsersIds)};
    auto addedUsersIds {core::EndpointUtils::getDifference(newUsersIds, oldUsersIds)};

    // adjust key
    if(moduleCurrentKey.dataStructureVersion < 2) {
        //force update all keys if thread keys is in older version
        _usersToAddMissingKey = _new_users;
    } else {
        for(auto new_user: _new_users) {
            if( std::find(addedUsersIds.begin(), addedUsersIds.end(), new_user.userId) != addedUsersIds.end()) {
                _usersToAddMissingKey.push_back(new_user);
            }
        }
    }
    _needNewKey = deletedUsersIds.size() > 0 || forceGenerateNewKey;
}

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_USERS_KEYS_RESOLVER_HPP_