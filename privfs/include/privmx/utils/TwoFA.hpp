/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_TWOFA_HPP_
#define _PRIVMXLIB_UTILS_TWOFA_HPP_

#include <Poco/JSON/Object.h>

namespace privmx {
namespace utils {

class TwoFA
{
public:
    static Poco::JSON::Object::Ptr generateToken(const std::string& secret);
    static Poco::JSON::Object::Ptr generateToken(const Poco::JSON::Object::Ptr data);
};

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_TWOFA_HPP_
