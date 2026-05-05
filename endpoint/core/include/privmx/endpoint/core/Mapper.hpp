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
    static CollectionItemChange mapToCollectionItemChange(const server::CollectionItemChange_c_struct& data);
    static std::vector<CollectionItemChange> mapToCollectionItemChanges(const std::vector<server::CollectionItemChange_c_struct>& data);
    static CollectionChangedEventData mapToCollectionChangedEventData(const std::string& moduleType, const server::CollectionChangedEventData_c_struct& data);
    static UserWithAction mapToUserWithAction(const server::ContextUsersStatusChange_c_struct& data);
    static std::vector<UserWithAction> mapToUserWithActions(const std::vector<server::ContextUsersStatusChange_c_struct>& data);
    static ContextUsersStatusChangedEventData mapToContextUsersStatusChangedEventData(const server::ContextUsersStatusChangeEventData_c_struct& data);
    static ContextUserEventData mapToContextUserEventData(const server::ContextUserEventData_c_struct& data);
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_MAPPER_HPP_
