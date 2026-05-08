/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/UsersKeysResolver.hpp"

using namespace privmx::endpoint::core;

std::shared_ptr<UsersKeysResolver> UsersKeysResolver::create(
        const std::vector<std::string>& currentUserIds,
        const std::vector<std::string>& currentManagerIds,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const bool forceGenerateNewKey,
        const DecryptedEncKeyV2& moduleCurrentKey
) {
    auto instance = std::make_shared<UsersKeysResolver>();
    instance->init(currentUserIds, currentManagerIds, users, managers, forceGenerateNewKey, moduleCurrentKey);
    return instance;
}

void UsersKeysResolver::init(
        const std::vector<std::string>& currentUserIds,
        const std::vector<std::string>& currentManagerIds,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const bool forceGenerateNewKey,
        const DecryptedEncKeyV2& moduleCurrentKey
) {
    auto oldUsersIds {core::EndpointUtils::uniqueList(currentUserIds, currentManagerIds)};

    _new_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    auto newUsersIds {core::EndpointUtils::usersWithPubKeyToIds(_new_users)};
    auto deletedUsersIds {core::EndpointUtils::getDifference(oldUsersIds, newUsersIds)};
    auto addedUsersIds {core::EndpointUtils::getDifference(newUsersIds, oldUsersIds)};

    if(moduleCurrentKey.dataStructureVersion < 2) {
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

std::vector<UserWithPubKey> UsersKeysResolver::getUsersToAddKey() {
    return _usersToAddMissingKey;
}

std::vector<UserWithPubKey> UsersKeysResolver::getNewUsers() {
    return _new_users;
}

bool UsersKeysResolver::doNeedNewKey() {
    return _needNewKey;
}
