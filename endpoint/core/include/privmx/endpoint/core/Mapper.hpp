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
    static CollectionItemChange mapToCollectionChangeItem(const server::CollectionItemChange& data);
    static std::vector<CollectionItemChange> mapToCollectionChangeItems(const privmx::utils::List<server::CollectionItemChange>& data);
    static CollectionChangeEventData mapToCollectionChangeEventData(const std::string& moduleType, const server::CollectionChangeEventData& data);
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_MAPPER_HPP_
