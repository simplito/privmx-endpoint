/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_MODULEBASEAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_MODULEBASEAPI_HPP_

#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <functional>
#include <vector>
#include <map>

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/EventChannelManager.hpp>
#include <privmx/endpoint/core/SubscriptionHelper.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>

#include "privmx/endpoint/core/Factory.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class ModuleBaseApi
{
public:
    ModuleBaseApi(
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::string& host,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
        const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
        const core::Connection& connection
    );
    virtual ~ModuleBaseApi() = default;
protected:
    template<typename ModuleStructAsTypedObj>
    auto getAndValidateModuleCurrentEncKey(ModuleStructAsTypedObj moduleObj) -> decltype(moduleObj.data(), moduleObj.contextId(), moduleObj.keys(), moduleObj.resourceId(), core::DecryptedEncKey());

    template<typename ModuleStructAsTypedObj>
    auto getModuleEncKeyLocation(ModuleStructAsTypedObj moduleObj, const std::string& resourceId) -> decltype(moduleObj.contextId(), core::EncKeyLocation());

    template<typename ModuleStructAsTypedObj>
    auto getAndValidateModuleKeys(ModuleStructAsTypedObj moduleObj, const std::string& resourceId) -> decltype(moduleObj.contextId(), moduleObj.keys(), moduleObj.resourceId(), std::unordered_map<std::string, DecryptedEncKeyV2>());

    DecryptedEncKeyV2 findEncKeyByKeyId(std::unordered_map<std::string, DecryptedEncKeyV2> keys, const std::string& keyId);

private:
    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::string _host;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    core::Connection _connection;
};


template<typename ModuleStructAsTypedObj>
auto ModuleBaseApi::getAndValidateModuleCurrentEncKey(ModuleStructAsTypedObj moduleObj) -> decltype(moduleObj.data(), moduleObj.contextId(), moduleObj.keys(), moduleObj.resourceId(), core::DecryptedEncKey()) {
    auto data_entry = moduleObj.data().get(moduleObj.data().size()-1);
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    auto location {getModuleEncKeyLocation(moduleObj, moduleObj.resourceIdOpt(""))};
    keyProviderRequest.addOne(moduleObj.keys(), data_entry.keyId(), location);
    core::DecryptedEncKey ret = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(data_entry.keyId());
    return ret;
}

template<typename ModuleStructAsTypedObj>
auto ModuleBaseApi::getModuleEncKeyLocation(ModuleStructAsTypedObj moduleObj, const std::string& resourceId) -> decltype(moduleObj.contextId(), core::EncKeyLocation()) {
    core::EncKeyLocation location{.contextId=moduleObj.contextId(), .resourceId=resourceId};
    return location;
}

template<typename ModuleStructAsTypedObj>
auto ModuleBaseApi::getAndValidateModuleKeys(ModuleStructAsTypedObj moduleObj, const std::string& resourceId) -> decltype(moduleObj.contextId(), moduleObj.keys(), moduleObj.resourceId(), std::unordered_map<std::string, DecryptedEncKeyV2>()) {
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    auto location {getModuleEncKeyLocation(moduleObj, resourceId)};
    keyProviderRequest.addAll(moduleObj.keys(), location);
    auto moduleKeys {_keyProvider->getKeysAndVerify(keyProviderRequest).at(location)};
    return moduleKeys;
}

} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADAPIIMPL_HPP_
