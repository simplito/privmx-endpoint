/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_LISTQUERYMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_LISTQUERYMAPPER_HPP_

#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class ListQueryMapper {
public:
    static void map(server::ListModel obj, const PagingQuery& listQuery) {
        obj.sortOrder(listQuery.sortOrder);
        obj.limit(listQuery.limit);
        obj.skip(listQuery.skip);
        if (listQuery.lastId.has_value()) {
            obj.lastId(listQuery.lastId.value());
        }
        if(listQuery.queryJSONString.has_value()) {
            obj.query(privmx::utils::Utils::parseJson(listQuery.queryJSONString.value()));
        }
    }
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_LISTQUERYMAPPER_HPP_
