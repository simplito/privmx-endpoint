/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_FACTORY_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_FACTORY_HPP_

#include <string>
#include "privmx/utils/Utils.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include <Poco/JSON/Object.h>

namespace privmx {
namespace endpoint {
namespace core {

class Factory {
public:
    static Poco::Dynamic::Var createPolicyServerObject(const ContainerPolicy& policy);
    static Poco::Dynamic::Var createPolicyServerObject(const ContainerPolicyWithoutItem& policy);
    static ContainerPolicy parsePolicyServerObject(const Poco::Dynamic::Var& serverPolicyObject);
    static ContainerPolicyWithoutItem parsePolicyServerObjectWithoutItem(const Poco::Dynamic::Var& serverPolicyObject);
private:
    template<typename T>
    inline static std::optional<T> getValueOrNullopt(const Poco::JSON::Object::Ptr policyJsonObj, const std::string& key);
};


template<typename T>
inline std::optional<T> Factory::getValueOrNullopt(const Poco::JSON::Object::Ptr policyJsonObj, const std::string& key) {
    Poco::Dynamic::Var valueFromKey = policyJsonObj->get(key);
    if (valueFromKey.isEmpty()) {
        return std::nullopt;
    } 
    return policyJsonObj->getValue<T>(key);
}


}
}
}

#endif // _PRIVMXLIB_ENDPOINT_CORE_FACTORY_HPP_
