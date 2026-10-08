#ifndef _PRIVMXLIB_ENDPOINT_CORE_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EXCEPTION_HPP_

#include <exception>
#include <initializer_list>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace privmx {
namespace endpoint {
namespace core {

constexpr bool exceptionCodesUnique(std::initializer_list<unsigned int> codes) {
    for (auto i = codes.begin(); i != codes.end(); ++i) {
        for (auto j = i + 1; j != codes.end(); ++j) {
            if (*i == *j) {
                return false;
            }
        }
    }
    return true;
}

class Exception : public std::exception {
public:
    // name and scope are stored as views, so they must outlive the exception
    // all declarations go through the DECLARE_*_EXCEPTION macros, which pass string literals
    Exception(
        std::string msg = std::string(),
        std::string_view name = std::string_view(),
        std::string_view scope = std::string_view(),
        unsigned int code = 0,
        std::string description = std::string()
    )
        : _msg(std::move(msg)), _name(name), _scope(scope), _code(code), _description(std::move(description)),
          _what(_description.empty() ? _msg : (_msg + " : " + _description)) {}
    Exception(
        std::string msg,
        std::string_view name,
        std::string_view scope,
        unsigned int code,
        std::string description,
        const Exception& cause
    )
        : _msg(std::move(msg)), _name(name), _scope(scope), _code(code), _description(std::move(description)),
          _what(
              _description.empty() ? (_msg + " | caused by: " + cause.what()) :
                                     (_msg + " : " + _description + " | caused by: " + cause.what())
          ),
          _cause(std::make_shared<const Exception>(cause)) {}
    virtual const char* what() const noexcept override { return _what.c_str(); }
    std::string getName() const noexcept;
    std::string getScope() const noexcept;
    unsigned int getCode() const noexcept;
    std::string getDescription() const noexcept;
    std::string getFull(bool JSON = false) const noexcept;
    std::shared_ptr<const Exception> getCause() const noexcept { return _cause; }
    virtual void rethrow() const;

private:
    std::string _msg;
    std::string_view _name;
    std::string_view _scope;
    unsigned int _code;
    std::string _description;
    std::string _what; // _what = _msg + _description + _cause
    std::shared_ptr<const Exception> _cause;
};

inline std::string Exception::getName() const noexcept {
    return std::string(_name);
}

inline std::string Exception::getScope() const noexcept {
    return std::string(_scope);
}

inline unsigned int Exception::getCode() const noexcept {
    return _code;
}

inline std::string Exception::getDescription() const noexcept {
    return _description;
}

inline std::string Exception::getFull(bool JSON) const noexcept {
    if (JSON) {
        std::string res = "";
        res += "{";
        res += "\"name\" : \"";
        res += _name;
        res += "\",";
        res += "\"scope\" : \"";
        res += _scope;
        res += "\",";
        res += "\"msg\" : \"" + _msg + "\",";
        res += "\"code\" : " + std::to_string(_code) + ",";
        res += "\"description\" : \"" + _description + "\",";
        res += "\"cause\" : " + (_cause ? _cause->getFull(true) : std::string("null"));
        res += "}";
        return res;
    }
    std::string res = "";

    res += "[";
    res += _scope;
    res += "]";
    res += ":" + _what + " ";
    res += _name;
    res += " (code: " + std::to_string(_code);
    res += ", msg: \"" + _msg + "\")";
    res += "\n\nDescription: \n" + _description;
    if (_cause) {
        res += "\n\nCaused by:\n" + _cause->getFull(false);
    }
    return res;
}

inline void Exception::rethrow() const {
    throw *this;
}

// used scope codes
// 0x0000 - Unknown
// 0x0001 - Core
// 0x0002 - Connection
// 0x0003 - Thread
// 0x0004 - Store
// 0x0005 - Interface
// 0x0007 - Inbox
// 0x0008 - Stream
// 0x0009 - Event
// 0x000A - Kvdb
// 0x000B - Search
// 0x000C - Lock
// 0x000D - Group
// Form 0xE000 to 0xEFFF - Internal (PrivmxExtException)
// Form 0xF000 to 0xFFFF - Server
//

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_EXCEPTION_HPP_
