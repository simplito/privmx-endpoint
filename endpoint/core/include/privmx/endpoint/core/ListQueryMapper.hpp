#ifndef _PRIVMXLIB_ENDPOINT_CORE_LISTQUERYMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_LISTQUERYMAPPER_HPP_

#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class ListQueryMapper {
public:
    template<class T>
    static void map(T& obj, const PagingQuery& listQuery) {
        obj.sortOrder(listQuery.sortOrder);
        obj.limit(listQuery.limit);
        obj.skip(listQuery.skip);
        if (listQuery.lastId.has_value()) {
            obj.lastId(listQuery.lastId.value());
        }
    }
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_LISTQUERYMAPPER_HPP_
