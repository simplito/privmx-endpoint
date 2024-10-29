#ifndef _PRIVMXLIB_ENDPOINT_CORE_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_TYPES_HPP_

#include <optional>
#include <string>
#include <vector>

namespace privmx {
namespace endpoint {
namespace core {

template<typename T>

/**
* Contains results of listing methods.
*/
 struct PagingList {
    /**
     * total items available to get
     */
    int64_t totalAvailable;

    /**
     * list of items read during single method call
     */
    std::vector<T> readItems;
};

/**
 * Contains query parameters for methods returning lists (PagingList).
 */
struct PagingQuery {
    /**
     * number of elements to skip from result
     */
    int64_t skip;

    /**
     * limit of elements to return for query
     */
    int64_t limit;

    /**
     * order of elements in result ("asc" for ascending, "desc" for descending)
     */
    std::string sortOrder;

    /**
     * ID of the element from which query results should start
     */
    std::optional<std::string> lastId;
};

/**
 * Contains base Context information.
 */
struct Context {
    /**
     * ID of the user requesting information
     */
    std::string userId;

    /**
     * ID of the Context
     */
    std::string contextId;
};

/**
 * Contains ID of a user and the corresponding public key.
 */
struct UserWithPubKey {
    /**
     * ID of the user
     */
    std::string userId;

    /**
     * user's public key
     */
    std::string pubKey;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_TYPES_HPP_
