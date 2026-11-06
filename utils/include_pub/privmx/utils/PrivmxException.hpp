/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_PRIVMXEXCEPTION_HPP_
#define _PRIVMXLIB_UTILS_PRIVMXEXCEPTION_HPP_

#include <privmx/endpoint/core/Exception.hpp>

namespace privmx {
namespace utils {

// deprecated spelling of the one exception base class; kept so the existing catch sites keep compiling
using PrivmxException = privmx::endpoint::core::Exception;

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_PRIVMXEXCEPTION_HPP_
