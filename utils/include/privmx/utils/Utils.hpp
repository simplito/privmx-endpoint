/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_UTILS_HPP_
#define _PRIVMXLIB_UTILS_UTILS_HPP_

#include <string>
#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>
#include <Poco/Types.h>


namespace privmx {
namespace utils {

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
    static std::string decode(const std::string& base32_data);
    static std::string encode(const std::string& data);
    static bool is(const std::string& data);
};

class Base64
{
public:
    static std::string from(const std::string& data, int line_length = 0);
    static std::string toString(const std::string& base64_data);
    static bool is(const std::string& data);
};

class TimestampService
{
public:
    using Ptr = Poco::SharedPtr<TimestampService>;

    virtual Poco::Int64 getNowTimestamp() = 0;
    virtual ~TimestampService() {}
};

class TimestampServiceImpl : public TimestampService
{
public:
    Poco::Int64 getNowTimestamp();
};

class Utils
{
public:
    static std::string fillTo32(const std::string& data);
    static std::string removeEscape(const std::string& data);
    static std::string formatToBase32(const std::string& data);
    static Poco::Int64 getNowTimestamp();
    static std::string getNowTimestampStr();
    static std::string stringifyVar(const Poco::Dynamic::Var& var, bool pretty = false);
    static std::string stringify(const Poco::JSON::Array::Ptr& arr, bool pretty = false);
    static std::string stringify(const Poco::JSON::Object::Ptr& obj, bool pretty = false);
    static Poco::Dynamic::Var parseJson(const std::string& json);
    static Poco::JSON::Object::Ptr parseJsonObject(const std::string& json);
    static Poco::JSON::Array::Ptr jsonArrayDeepCopy(const Poco::JSON::Array::Ptr& arr);
    static Poco::JSON::Object::Ptr jsonObjectDeepCopy(const Poco::JSON::Object::Ptr& obj);
    static std::string jsonArrayJoin(const Poco::JSON::Array::Ptr& arr);
    static std::string trim(const std::string& data);
    static std::vector<std::string> split(std::string data, const std::string& delimiter);

    static std::vector<std::string> parseIniFileLine(const std::string& str, char character);
    static void ltrim(std::string& s);
    static void rtrim(std::string& s);

    static TimestampService::Ptr timestamp_service;
};

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_UTILS_HPP_
