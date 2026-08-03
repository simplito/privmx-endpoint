/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_DYNAMICTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_DYNAMICTYPES_HPP_

#include <privmx/utils/JsonHelper.hpp>
#include <string>

namespace privmx {
namespace endpoint {
namespace search {
namespace dynamic {

#define INDEX_DATA_FIELDS(F)                                                                                           \
    F(storeId, std::string)                                                                                            \
    F(mode, int64_t)
JSON_STRUCT(IndexData, INDEX_DATA_FIELDS);

#define LOCK_FIELDS(F)                                                                                                 \
    F(lockId, std::string)                                                                                             \
    F(level, int64_t)                                                                                                  \
    F(timestamp, int64_t)
JSON_STRUCT(Lock, LOCK_FIELDS);

#define LOCK_SET_FIELDS(F)                                                                                             \
    F(writerLock, Lock)                                                                                                \
    F(readerLocks, std::map<std::string, Lock>)
JSON_STRUCT(LockSet, LOCK_SET_FIELDS);

} // namespace dynamic
} // namespace search
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_SEARCH_DYNAMICTYPES_HPP_
