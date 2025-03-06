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

    /**
     * Encode buffer to sting in Hex format
     *
     * @param data buffer to encode
     * 
     * @return string in Hex format
     */
    static std::string encode(const Buffer& data);

    /**
     * Decode string in Hex to buffer
     *
     * @param hex_data string to decode
     * 
     * @return buffer with decoded data
     */
    static Buffer decode(const std::string& hex_data);

    /**
     * Check if given string is in Hex format
     *
     * @param data string to check
     * 
     * @return data check result
     */
    static bool is(const std::string& data);
};

class Base32
{
public:

    /**
     * Encode buffer to sting in Base32 format
     *
     * @param data buffer to encode
     * 
     * @return string in Base32 format
     */
    static std::string encode(const Buffer& data);

    /**
     * Decode string in Base32 to buffer
     *
     * @param hex_data string to decode
     * 
     * @return buffer with decoded data
     */
    static Buffer decode(const std::string& base32_data);

    /**
     * Check if given string is in Base32 format
     *
     * @param data string to check
     * 
     * @return data check result
     */
    static bool is(const std::string& data);
};

class Base64
{
public:

    /**
     * Encode buffer to sting in Base64 format
     *
     * @param data buffer to encode
     * 
     * @return string in Base64 format
     */
    static std::string encode(const Buffer& data);

    /**
     * Decode string in Base64 to buffer
     *
     * @param hex_data string to decode
     * 
     * @return buffer with decoded data
     */
    static Buffer decode(const std::string& base64_data);

    /**
     * Check if given string is in Base64 format
     *
     * @param data string to check
     * 
     * @return data check result
     */
    static bool is(const std::string& data);
};

class Utils
{
public:

    /**
     * Remove all trailing whitespace
     *
     * @param data 
     * 
     * @return copy of string with removed trailing whitespace.
     */
    static std::string trim(const std::string& data);

    /**
     * split string by given delimiter (delimiter is removed)
     *
     * @param data string to split
     * @param delimiter string witch will be splitted
     * @return vector containing all splitted parts
     */
    static std::vector<std::string> split(std::string data, const std::string& delimiter);

    /**
     * Remove all whitespaces from left of given string
     *
     * @param data reference to string
     */
    static void ltrim(std::string& data);

    /**
     * Remove all whitespaces from right of given string
     *
     * @param data string to check
     */
    static void rtrim(std::string& data);
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_UTILS_HPP_
