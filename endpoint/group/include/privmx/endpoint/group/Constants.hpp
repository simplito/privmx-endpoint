#ifndef _PRIVMXLIB_ENDPOINT_GROUP_CONSTANTS_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_CONSTANTS_HPP_

#include <string>

namespace privmx {
namespace endpoint {
namespace group {

static constexpr char GROUP_TYPE_FILTER_FLAG[] = "group";
static constexpr char TREE_SCOPE_FULL[] = "full";

// The bridge caps a custom event's `data` at 16 KB. That budget holds a base64-encoded envelope, so the
// plaintext ceiling is 16 KB * 3/4 minus the envelope's header, signature and cipher overhead — call it 11 KB
// and leave the arithmetic a margin. Checking here turns a server rejection into a straight answer.
static constexpr size_t MAX_CUSTOM_EVENT_DATA = 11 * 1024;

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_CONSTANTS_HPP_
