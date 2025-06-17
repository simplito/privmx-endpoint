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

UsersKeysResolver::UsersKeysResolver(const std::vector<core::UserWithPubKey>& users,
            const std::vector<core::UserWithPubKey>& managers) : 
    _gateway(gateway), _eventMiddleware(eventMiddleware) {}

std::vector<core::UserWithPubKey> UsersKeysResolver::getUsersToAddKey() {
}

bool UsersKeysResolver::doNeedNewKey() {

}
