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

std::vector<UserWithPubKey> UsersKeysResolver::getUsersToAddKey() {
    return _usersToAddMissingKey;
}

std::vector<UserWithPubKey> UsersKeysResolver::getNewUsers() {
    return _new_users;
}

bool UsersKeysResolver::doNeedNewKey() {
    return _needNewKey;
}
