/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_BACKENDREQUESTERVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_BACKENDREQUESTERVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/core/c_api.h"
#include "privmx/endpoint/core/BackendRequester.hpp"
#include "privmx/endpoint/core/VarDeserializer.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class BackendRequesterVarInterface {
public:
    BackendRequesterVarInterface(const core::VarSerializer& serializer)
        : _serializer(serializer) {}

    Poco::Dynamic::Var backendRequest(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(privmx_BackendRequester_Method method, const Poco::Dynamic::Var& args);
private:
    static std::map<privmx_BackendRequester_Method, Poco::Dynamic::Var (BackendRequesterVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_BACKENDREQUESTERVARINTERFACE_HPP_
