/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_EXCEPTIONHANDLER_HPP_
#define _PRIVMXLIB_UTILS_EXCEPTIONHANDLER_HPP_

#include <exception>
#include <string>
#include <Poco/Dynamic/Var.h>
#include <Poco/Exception.h>
#include <Poco/JSON/Object.h>

#include <privmx/utils/PrivmxException.hpp>
#include "privmx/endpoint/core/Exception.hpp"
#include "privmx/endpoint/interface/InterfaceException.hpp"

namespace privmx {
namespace utils {

class ExceptionHandler
{
public:
    static Poco::Dynamic::Var make_error(const std::string& message = "Unknown");
    static Poco::Dynamic::Var make_error(const endpoint::core::Exception& e);
    static Poco::Dynamic::Var make_error(const utils::PrivmxException& e);
    static Poco::Dynamic::Var make_error(const Poco::Exception& e);
    static Poco::Dynamic::Var make_error(const std::exception& e);
};

inline Poco::Dynamic::Var ExceptionHandler::make_error(const std::string& message) {
    return make_error(endpoint::cinterface::UncaughtException(message));
}

inline Poco::Dynamic::Var ExceptionHandler::make_error(const endpoint::core::Exception& e) {
    Poco::JSON::Object::Ptr error = new Poco::JSON::Object();
    error->set("code", (int64_t)e.getCode());
    error->set("name", e.getName());
    error->set("scope", e.getScope());
    error->set("description", e.getDescription());
    error->set("full", e.getFull());
    error->set("__type", "Error");
    return error;
}

inline Poco::Dynamic::Var ExceptionHandler::make_error(const utils::PrivmxException& e) {
    std::string message = std::string("utils::PrivmxException: ") + e.what() +
        ", type: " + std::to_string(e.getType()) +
        ", code: " + std::to_string(e.getCode());
    return make_error(message);
}

inline Poco::Dynamic::Var ExceptionHandler::make_error(const Poco::Exception& e) {
    std::string message = std::string("Poco::Exception: ") + e.displayText();
    return make_error(message);
}

inline Poco::Dynamic::Var ExceptionHandler::make_error(const std::exception& e) {
    std::string message = std::string("std::exception: ") + e.what();
    return make_error(message);
}

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_EXCEPTIONHANDLER_HPP_
