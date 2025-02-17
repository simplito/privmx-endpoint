#ifndef _PRIVMXLIB_ENDPOINT_CORE_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EXCEPTION_HPP_

#include <exception>
#include <string>

namespace privmx {
namespace endpoint {
namespace core {

class Exception : public std::exception {
public:
    Exception(const std::string& msg = std::string(), const std::string& name = std::string(),
              const std::string& scope = std::string(), unsigned int code = 0,
              const std::string& description = std::string())
        : _msg(msg), _name(name), _scope(scope), _code(code), _description(description) {}
    virtual const char* what() const noexcept override { return _msg.c_str(); }
    std::string getName() const noexcept;
    std::string getScope() const noexcept;
    unsigned int getCode() const noexcept;
    std::string getDescription() const noexcept;
    std::string getFull(bool JSON = false) const noexcept;
    virtual void rethrow() const;

private:
    std::string _msg;
    std::string _name;
    std::string _scope;
    unsigned int _code;
    std::string _description;
};

inline std::string Exception::getName() const noexcept {
    return _name;
}

inline std::string Exception::getScope() const noexcept {
    return _scope;
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
        res += "\"name\" : \"" + _name + "\",";
        res += "\"scope\" : \"" + _scope + "\",";
        res += "\"msg\" : \"" + _msg + "\",";
        res += "\"code\" : " + std::to_string(_code) + ",";
        res += "\"description\" : \"" + _description + "\"";
        res += "}";
        return res;
    }
    std::string res = "";

    res += "[" + _scope + "]";
    res += " " + _name;
    res += " (code: " + std::to_string(_code);
    res += ", msg: \"" + _msg + "\")";
    res += "\n\nDescription: \n" + _description;
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
// 0x0009 - Event
// Form 0xE000 to 0xEFFF - Internal (PrivmxExtException)
// Form 0xF000 to 0xFFFF - Server
// 

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_EXCEPTION_HPP_
