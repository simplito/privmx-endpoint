/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_TYPEVALIDATOR_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_TYPEVALIDATOR_HPP_

#include <Poco/Dynamic/Var.h>

namespace privmx {
namespace endpoint {
namespace core {

class TypeValidator {
public:
    static void validateInteger(const Poco::Dynamic::Var& val, const std::string& name);
    static void validateString(const Poco::Dynamic::Var& val, const std::string& name);
    static void validateBuffer(const Poco::Dynamic::Var& val, const std::string& name);
    static void validateBoolean(const Poco::Dynamic::Var& val, const std::string& name);
    static void validateArray(const Poco::Dynamic::Var& val, const std::string& name);
    static void validateObject(const Poco::Dynamic::Var& val, const std::string& name);

private:
    static void validateNotEmpty(const Poco::Dynamic::Var& val, const std::string& name, const std::string& expected);
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_TYPEVALIDATOR_HPP_
