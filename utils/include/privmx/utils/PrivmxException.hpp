#ifndef _PRIVMXLIB_UTILS_PRIVMXEXCEPTION_HPP_
#define _PRIVMXLIB_UTILS_PRIVMXEXCEPTION_HPP_

#include <exception>
#include <string>

namespace privmx {
namespace utils {

class PrivmxException : public std::exception
{
public:

    enum Type {
        LIBRARY = 1,
        RPC = 2,
        ALERT = 3
    };

    PrivmxException(const std::string& msg = std::string(), Type type = LIBRARY, int code = 0, const std::string& data = "")
            : _msg(msg), _type(type), _code(code), _data(data) {}
    virtual const char* what() const noexcept override {
        return _msg.c_str();
    }
    const Type& getType() const noexcept;
    int getCode() const noexcept;
    std::string getData() const noexcept;
    bool hasTypeAndCode(const Type& type, int code) const noexcept;
    bool hasTypeAndMessage(const Type& type, const std::string& msg) const noexcept;
    virtual void rethrow() const;

private:
    std::string _msg;
    Type _type;
    int _code;
    std::string _data;
};

inline const PrivmxException::Type& PrivmxException::getType() const noexcept {
    return _type;
}

inline int PrivmxException::getCode() const noexcept {
    return _code;
}

inline std::string PrivmxException::getData() const noexcept {
    return _data;
}

inline bool PrivmxException::hasTypeAndCode(const PrivmxException::Type& type, int code) const noexcept {
    return (_type == type && _code == code);
}

inline bool PrivmxException::hasTypeAndMessage(const Type& type, const std::string& msg) const noexcept {
    return (_type == type && _msg == msg);
}

inline void PrivmxException::rethrow() const {
    throw *this;
}

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_PRIVMXEXCEPTION_HPP_
