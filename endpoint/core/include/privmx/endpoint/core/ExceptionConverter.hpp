/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_EXCEPTION_CONVERTER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EXCEPTION_CONVERTER_HPP_

#include "privmx/endpoint/core/CoreException.hpp"

namespace privmx {
namespace endpoint {
namespace core {

// deprecated: the lower layers throw core::Exception directly, so only the alert carrying
// "User doesn't exist" is still translated here, the transport cannot tell it from any other alert

class ExceptionConverter {
public:
    static Exception convert(const Exception& e);
    static void rethrowAsCoreException(const Exception& e);
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_EXCEPTION_CONVERTER_HPP_
