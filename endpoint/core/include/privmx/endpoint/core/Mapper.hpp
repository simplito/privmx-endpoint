/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_MAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_MAPPER_HPP_

#include "privmx/endpoint/core/Events.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class Mapper {
public:
    static CollectionItemChange mapToCollectionItemChange(const server::CollectionItemChange& data);
    static std::vector<CollectionItemChange> mapToCollectionItemChanges(const privmx::utils::List<server::CollectionItemChange>& data);
    static CollectionChangedEventData mapToCollectionChangedEventData(const std::string& moduleType, const server::CollectionChangedEventData& data);
    static UserWithAction mapToUserWithAction(const server::ContextUsersStatusChange& data);
    static std::vector<UserWithAction> mapToUserWithActions(const privmx::utils::List<server::ContextUsersStatusChange>& data);
    static ContextUsersStatusChangedEventData mapToContextUsersStatusChangedEventData(const server::ContextUsersStatusChangeEventData& data);
    static ContextUserEventData mapToContextUserEventData(const server::ContextUserEventData& data);
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_MAPPER_HPP_
