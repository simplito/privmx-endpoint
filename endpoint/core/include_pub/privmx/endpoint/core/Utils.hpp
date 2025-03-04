#ifndef _PRIVMXLIB_ENDPOINT_CORE_UTILS_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_UTILS_HPP_

#include <optional>
#include <string>
#include <vector>

namespace privmx {
namespace endpoint {
namespace core {

class Hex
{
public:
    static std::string from(const std::string& data);
    static std::string toString(const std::string& hex_data);
    static bool is(const std::string& data);
};

class Base32
{
public:
    static std::string from(const std::string& data);
    static std::string toString(const std::string& base32_data);
    static bool is(const std::string& data);
};

class Base64
{
public:
    static std::string from(const std::string& data);
    static std::string toString(const std::string& base64_data);
    static bool is(const std::string& data);
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
