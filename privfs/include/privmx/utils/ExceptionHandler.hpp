/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_POCKET_EXCEPTIONHANDLER_HPP_
#define _PRIVMXLIB_POCKET_EXCEPTIONHANDLER_HPP_

#include <exception>
#include <string>
#include <Poco/Dynamic/Var.h>
#include <Poco/Exception.h>
#include <Poco/JSON/Object.h>

#include <privmx/utils/PrivmxException.hpp>

namespace privmx {
namespace utils {

class ExceptionHandler
{
public:
    static Poco::Dynamic::Var make_error(const std::string& message = "Unspecified error", int type = 0, int code = 0);
    static Poco::Dynamic::Var make_error(const utils::PrivmxException& e);
    static Poco::Dynamic::Var make_error(const Poco::Exception& e);
    static Poco::Dynamic::Var make_error(const std::exception& e);
};

inline Poco::Dynamic::Var ExceptionHandler::make_error(const std::string& message, int type, int code) {
    Poco::JSON::Object::Ptr error = new Poco::JSON::Object();
    error->set("type", type);
    error->set("code", code);
    error->set("message", message);
    error->set("__type", "Error");
    return error;
}

inline Poco::Dynamic::Var ExceptionHandler::make_error(const utils::PrivmxException& e) {
    return make_error(e.what(), e.getType(), e.getCode());
}

inline Poco::Dynamic::Var ExceptionHandler::make_error(const Poco::Exception& e) {
    return make_error(e.displayText());
}

inline Poco::Dynamic::Var ExceptionHandler::make_error(const std::exception& e) {
    return make_error(e.what());
}

} // pocket
} // privmx

#endif // _PRIVMXLIB_POCKET_EXCEPTIONHANDLER_HPP_
