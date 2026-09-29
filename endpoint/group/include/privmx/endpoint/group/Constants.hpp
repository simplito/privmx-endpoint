#ifndef _PRIVMXLIB_ENDPOINT_GROUP_CONSTANTS_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_CONSTANTS_HPP_

#include <string>

namespace privmx {
namespace endpoint {
namespace group {

static constexpr char GROUP_TYPE_FILTER_FLAG[] = "group";
static constexpr char TREE_SCOPE_FULL[] = "full";

// The bridge caps a custom event's `data` at 16 KB, holding a base64 envelope: 16 KB * 3/4 minus header,
// signature and cipher overhead, with a margin. Checking here turns a server rejection into a straight answer.
static constexpr size_t MAX_CUSTOM_EVENT_DATA = 11 * 1024;

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_CONSTANTS_HPP_
