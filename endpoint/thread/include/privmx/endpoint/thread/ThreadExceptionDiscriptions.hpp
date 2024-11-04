/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_EXT_EXCEPTION_DESC_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_EXT_EXCEPTION_DESC_HPP_

namespace privmx {
namespace endpoint {
namespace thread {

const char* const __ERR_DESC_NotInitializedException { "Endpoint was not initialized or disconnected" };

} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_EXT_EXCEPTION_DESC_HPP_