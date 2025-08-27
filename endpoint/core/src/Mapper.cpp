/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/core/Mapper.hpp"

using namespace privmx::endpoint::core;

UserWithAction Mapper::mapToUserWithAction(const server::ContextUsersStatusChange& data) {
    return {
        .user = {
            .userId = data.userId(),
            .pubKey = data.pubKey()
        },
        .action = data.action()
    };
}

std::vector<UserWithAction> Mapper::mapToUserWithActions(const privmx::utils::List<server::ContextUsersStatusChange>& data) {
    std::vector<UserWithAction> result;
    result.reserve(data.size());
    for (auto item : data) {
        result.push_back(mapToUserWithAction(item));
    }
    return result;
}

ContextUsersStatusChangeData Mapper::mapToContextUsersStatusChangeData(const server::ContextUsersStatusChangeEventData& data) {
    return {
        .contextId = data.contextId(),
        .users = mapToUserWithActions(data.users())
    };
}

ContextUserEventData Mapper::mapToContextUserEventData(const server::ContextUserEventData& data) {
    return {
        .contextId = data.contextId(),
        .user = {
            .userId = data.userId(),
            .pubKey = data.pubKey()
        }
    };
}
