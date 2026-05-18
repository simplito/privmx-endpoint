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

#include <string>

#include <privmx/utils/TypedObject.hpp>
#include <privmx/utils/TypesMacros.hpp>

namespace privmx {
namespace endpoint {
namespace search {
namespace dynamic {

DECLARE_CORE_TYPE(IndexData)
    STRING_FIELD(storeId)
    INT64_FIELD(mode)
TYPE_END

DECLARE_CORE_TYPE(Lock)
    STRING_FIELD(lockId)
    INT64_FIELD(level)
    INT64_FIELD(timestamp)
TYPE_END

DECLARE_CORE_TYPE(LockSet)
    OBJECT_FIELD(writerLock, Lock)
    MAP_FIELD(readerLocks, Lock)
TYPE_END

} // dynamic
} // search
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_SEARCH_DYNAMICTYPES_HPP_
