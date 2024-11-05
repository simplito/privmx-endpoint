/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/varinterface/BackendRequesterVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/EventVarSerializer.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint::core;

std::map<BackendRequesterVarInterface::METHOD, Poco::Dynamic::Var (BackendRequesterVarInterface::*)(const Poco::Dynamic::Var&)>
    BackendRequesterVarInterface::methodMap = {{BackendRequest, &BackendRequesterVarInterface::backendRequest}};

Poco::Dynamic::Var BackendRequesterVarInterface::backendRequest(const Poco::Dynamic::Var& args) {
    Poco::JSON::Array::Ptr argsArr = VarInterfaceUtil::validateAndExtractArray(args, 3, 6);
    if (argsArr->size() == 3) {
        auto serverUrl = _deserializer.deserialize<std::string>(argsArr->get(0), "serverUrl");
        auto method = _deserializer.deserialize<std::string>(argsArr->get(1), "method");
        auto paramsAsJson = _deserializer.deserialize<std::string>(argsArr->get(2), "paramsAsJson");
        return core::BackendRequester::backendRequest(serverUrl, method, paramsAsJson);
    } else if (argsArr->size() == 4) {
        auto serverUrl = _deserializer.deserialize<std::string>(argsArr->get(0), "serverUrl");
        auto accessToken = _deserializer.deserialize<std::string>(argsArr->get(1), "accessToken");
        auto method = _deserializer.deserialize<std::string>(argsArr->get(2), "method");
        auto paramsAsJson = _deserializer.deserialize<std::string>(argsArr->get(3), "paramsAsJson");
        return core::BackendRequester::backendRequest(serverUrl, accessToken, method, paramsAsJson);
    } else if (argsArr->size() == 5) {
        throw core::InvalidNumberOfParamsException();
    } else {
        auto serverUrl = _deserializer.deserialize<std::string>(argsArr->get(0), "serverUrl");
        auto apiKeyId = _deserializer.deserialize<std::string>(argsArr->get(1), "apiKeyId");
        auto apiKeySecret = _deserializer.deserialize<std::string>(argsArr->get(2), "apiKeySecret");
        auto mode = _deserializer.deserialize<int64_t>(argsArr->get(3), "mode");
        auto method = _deserializer.deserialize<std::string>(argsArr->get(4), "method");
        auto paramsAsJson = _deserializer.deserialize<std::string>(argsArr->get(5), "paramsAsJson");
        return core::BackendRequester::backendRequest(serverUrl, apiKeyId, apiKeySecret, mode, method, paramsAsJson);
    }
}

Poco::Dynamic::Var BackendRequesterVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
