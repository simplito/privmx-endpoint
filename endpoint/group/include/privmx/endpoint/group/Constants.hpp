#ifndef _PRIVMXLIB_ENDPOINT_GROUP_CONSTANTS_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_CONSTANTS_HPP_

#include <string>

namespace privmx {
namespace endpoint {
namespace group {

static constexpr char GROUP_TYPE_FILTER_FLAG[] = "group";

// How much of the tree `groupGet` should send. The default is the caller's own path, which is what climbing and
// reading need; an operation that submits a whole new tree has to ask for the whole one (BR-10/EP-07).
static constexpr char TREE_SCOPE_FULL[] = "full";

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_CONSTANTS_HPP_
