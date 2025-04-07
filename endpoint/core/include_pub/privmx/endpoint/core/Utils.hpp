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
     * Encodes buffer to a string in Hex format.
     *
     * @param data buffer to encode
     * 
     * @return string in Hex format
     */
    static std::string encode(const Buffer& data);

    /**
     * Decodes string in Hex to buffer.
     *
     * @param hex_data string to decode
     * 
     * @return buffer with decoded data
     */
    static Buffer decode(const std::string& hex_data);

    /**
     * Checks if given string is in Hex format.
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
     * Encodes buffer to string in Base32 format.
     *
     * @param data buffer to encode
     * 
     * @return string in Base32 format
     */
    static std::string encode(const Buffer& data);

    /**
     * Decodes string in Base32 to buffer.
     *
     * @param hex_data string to decode
     * 
     * @return buffer with decoded data
     */
    static Buffer decode(const std::string& base32_data);

    /**
     * Checks if given string is in Base32 format.
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
     * Encodes buffer to string in Base64 format.
     *
     * @param data buffer to encode
     * 
     * @return string in Base64 format
     */
    static std::string encode(const Buffer& data);

    /**
     * Decodes string in Base64 to buffer.
     *
     * @param hex_data string to decode
     * 
     * @return buffer with decoded data
     */
    static Buffer decode(const std::string& base64_data);

    /**
     * Checks if given string is in Base64 format.
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
     * Removes all trailing whitespace.
     *
     * @param data 
     * 
     * @return copy of string with removed trailing whitespace.
     */
    static std::string trim(const std::string& data);

    /**
     * Splits string by given delimiter (delimiter is removed).
     *
     * @param data string to split
     * @param delimiter string which will be split
     * @return vector containing all split parts
     */
    static std::vector<std::string> split(std::string data, const std::string& delimiter);

    /**
     * Removes all whitespace from the left of given string.
     *
     * @param data reference to string
     */
    static void ltrim(std::string& data);

    /**
     * Removes all whitespace from the right of given string.
     *
     * @param data string to check
     */
    static void rtrim(std::string& data);

    /**
     * Generate random number on full range of int64_t
     */
    static int64_t generateRandomNumber();
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_UTILS_HPP_
