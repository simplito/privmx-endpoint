/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_DYNAMICTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_DYNAMICTYPES_HPP_

#include <string>

#include <privmx/endpoint/core/TypesMacros.hpp>

namespace privmx {
namespace endpoint {
namespace stream {
namespace dynamic {
//V4

ENDPOINT_CLIENT_TYPE(VersionedData)
    INT64_FIELD(version)
TYPE_END

} // dynamic
} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_DYNAMICTYPES_HPP_
