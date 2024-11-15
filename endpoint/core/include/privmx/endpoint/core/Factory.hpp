/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_TYPEDOBJECTFACTORY_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_TYPEDOBJECTFACTORY_HPP_

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
    static ContainerPolicy parsePolicyServerObject(const Poco::Dynamic::Var serverPolicyObject);
};


}
}
}

#endif // _PRIVMXLIB_ENDPOINT_CORE_TYPEDOBJECTFACTORY_HPP_
