#ifndef _PRIVMXLIB_UTILS_EXCEPTIONHANDLER_HPP_
#define _PRIVMXLIB_UTILS_EXCEPTIONHANDLER_HPP_

#include <exception>
#include <string>
#include <Poco/Dynamic/Var.h>
#include <Poco/Exception.h>
#include <Poco/JSON/Object.h>

#include <privmx/utils/PrivmxException.hpp>
#include "privmx/endpoint/core/Exception.hpp"

namespace privmx {
namespace utils {

class ExceptionHandler
{
public:
    static Poco::Dynamic::Var make_error(const std::string& message = "Unspecified error", int type = 0, int code = 0);
    static Poco::Dynamic::Var make_error(const endpoint::core::Exception& e);
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
    return make_error(e.what(), e.getType(), e.getCode());
}

inline Poco::Dynamic::Var ExceptionHandler::make_error(const Poco::Exception& e) {
    return make_error(e.displayText());
}

inline Poco::Dynamic::Var ExceptionHandler::make_error(const std::exception& e) {
    return make_error(e.what());
}

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_EXCEPTIONHANDLER_HPP_
