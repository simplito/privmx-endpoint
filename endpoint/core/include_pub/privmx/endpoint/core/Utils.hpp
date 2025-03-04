#ifndef _PRIVMXLIB_ENDPOINT_CORE_UTILS_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_UTILS_HPP_

#include <optional>
#include <string>
#include <vector>
#include "privmx/endpoint/core/Buffer.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class Hex
{
public:
    static Buffer encode(const Buffer& data);
    static Buffer decode(const Buffer& hex_data);
    static bool is(const Buffer& data);
};

class Base32
{
public:
    static Buffer encode(const Buffer& data);
    static Buffer decode(const Buffer& base32_data);
    static bool is(const Buffer& data);
};

class Base64
{
public:
    static Buffer encode(const Buffer& data);
    static Buffer decode(const Buffer& base64_data);
    static bool is(const Buffer& data);
};

class Utils
{
public:
    static std::string fillTo32(const std::string& data);
    static std::string removeEscape(const std::string& data);
    static std::string formatToBase32(const std::string& data);
    static std::string trim(const std::string& data);
    static std::vector<std::string> split(std::string data, const std::string& delimiter);
    static std::vector<std::string> splitStringByCharacter(const std::string& data, char character);
    static void ltrim(std::string& data);
    static void rtrim(std::string& data);
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_UTILS_HPP_
