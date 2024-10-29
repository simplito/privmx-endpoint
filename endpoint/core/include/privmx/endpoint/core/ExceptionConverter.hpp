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
    
};

} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_EXCEPTION_CONVERTER_HPP_