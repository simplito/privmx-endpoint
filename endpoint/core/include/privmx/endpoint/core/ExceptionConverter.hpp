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
#include "privmx/utils/PrivmxException.hpp"
#include <optional>
#include <optional>

namespace privmx {
namespace endpoint {
namespace core {

class ExceptionConverter {
public:
    static privmx::endpoint::core::Exception convert(const privmx::utils::PrivmxException& e);
    static void rethrowAsCoreException(const privmx::utils::PrivmxException& e);
    static int64_t getCodeOfUserVerificationFailureException();
    
};

} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_EXCEPTION_CONVERTER_HPP_