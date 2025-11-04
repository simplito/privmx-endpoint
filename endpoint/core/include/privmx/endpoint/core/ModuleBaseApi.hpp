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
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV5.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include "privmx/endpoint/core/Factory.hpp"
#include "privmx/endpoint/core/ContainerKeyCache.hpp"
#include <privmx/utils/GuardedExecutor.hpp>

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
        const core::Connection& connection
    );
    

    virtual ~ModuleBaseApi() = default;
protected:

    template<typename ModuleStructAsTypedObj>
    auto decryptModuleDataV4(
        ModuleStructAsTypedObj moduleObj, const core::DecryptedEncKey& encKey
    ) -> decltype(
        moduleObj.keyId(), moduleObj.data(), 
        core::DecryptedModuleDataV4()
    );

    template<typename ModuleStructAsTypedObj>
    auto decryptModuleDataV5(
        ModuleStructAsTypedObj moduleObj, const core::DecryptedEncKey& encKey
    ) -> decltype(
        moduleObj.keyId(), moduleObj.data(), 
        core::DecryptedModuleDataV5()
    );

    template<typename ModuleStructAsTypedObj>
    auto extractAndDecryptModuleInternalMeta(
        ModuleStructAsTypedObj moduleObj, const core::DecryptedEncKey& encKey
    ) -> decltype(
        moduleObj.keyId(), moduleObj.data(), 
        core::ModuleInternalMetaV5()
    );

    template<typename ModuleStructAsTypedObj>
    auto getAndValidateModuleCurrentEncKey(ModuleStructAsTypedObj moduleObj) -> decltype(moduleObj.data(), moduleObj.contextId(), moduleObj.keys(), moduleObj.resourceId(), core::DecryptedEncKeyV2());
    core::DecryptedEncKeyV2 getAndValidateModuleCurrentEncKey(ModuleKeys moduleKeys);

    template<typename ModuleStructAsTypedObj>
    auto getModuleEncKeyLocation(ModuleStructAsTypedObj moduleObj, const std::string& resourceId) -> decltype(moduleObj.contextId(), core::EncKeyLocation());

    template<typename ModuleStructAsTypedObj>
    auto getAndValidateModuleKeys(ModuleStructAsTypedObj moduleObj, const std::string& resourceId) -> decltype(moduleObj.contextId(), moduleObj.keys(), moduleObj.resourceId(), std::unordered_map<std::string, DecryptedEncKeyV2>());

    DecryptedEncKeyV2 findEncKeyByKeyId(std::unordered_map<std::string, DecryptedEncKeyV2> keys, const std::string& keyId);
    
    ModuleKeys getModuleKeys(
        const std::string& moduleId, 
        const std::optional<std::set<std::string>>& keyIds = std::nullopt, 
        const std::optional<int64_t>& minimumSchemaVersion = std::nullopt
    );
    virtual std::pair<ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string moduleId) = 0;
    ModuleKeys getNewModuleKeysAndUpdateCache(const std::string& moduleId);
    void setNewModuleKeysInCache(const std::string& moduleId, const ModuleKeys& newKeys, int64_t moduleVersion);
    void invalidateModuleKeysInCache(const std::optional<std::string>& moduleId = std::nullopt);

    

    std::shared_ptr<privmx::utils::GuardedExecutor> _guardedExecutor;
private:
    static core::ContainerKeyCache::CachedModuleKeys convertModuleKeysToContainerKeyCacheFormat(const ModuleKeys& moduleKeys, int64_t moduleVersion);
    static ModuleKeys convertContainerKeyCacheModuleKeysToModuleApiFormat(const core::ContainerKeyCache::CachedModuleKeys& moduleKeys);

    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::string _host;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    core::Connection _connection;
    core::ModuleDataEncryptorV4 _moduleDataEncryptorV4;
    core::ModuleDataEncryptorV5 _moduleDataEncryptorV5;
    core::ContainerKeyCache _keyCache;
};

template<typename ModuleStructAsTypedObj>
auto ModuleBaseApi::decryptModuleDataV4(
    ModuleStructAsTypedObj moduleObj, const core::DecryptedEncKey& encKey
) -> decltype(
    moduleObj.keyId(), moduleObj.data(), 
    core::DecryptedModuleDataV4()
) {
    try {
        auto encryptedData = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::EncryptedModuleDataV4>(moduleObj.data());
        return _moduleDataEncryptorV4.decrypt(encryptedData, encKey.key);
    } catch (const core::Exception& e) {
        return core::DecryptedModuleDataV4{{.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_4, .statusCode = e.getCode()}, {},{},{},{}};
    } catch (const privmx::utils::PrivmxException& e) {
        return core::DecryptedModuleDataV4{{.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_4, .statusCode = core::ExceptionConverter::convert(e).getCode()}, {},{},{},{}};
    } catch (...) {
        return core::DecryptedModuleDataV4{{.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_4, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE}, {},{},{},{}};
    }
}

template<typename ModuleStructAsTypedObj>
auto ModuleBaseApi::decryptModuleDataV5(
    ModuleStructAsTypedObj moduleObj, const core::DecryptedEncKey& encKey
) -> decltype(
    moduleObj.keyId(), moduleObj.data(), 
    core::DecryptedModuleDataV5()
) {
    try {
        auto encryptedData = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::EncryptedModuleDataV5>(moduleObj.data());
        if(encKey.statusCode != 0) {
            auto tmp = _moduleDataEncryptorV5.extractPublic(encryptedData);
            tmp.statusCode = encKey.statusCode;
            return tmp;
        }
        return _moduleDataEncryptorV5.decrypt(encryptedData, encKey.key);
    } catch (const core::Exception& e) {
        return core::DecryptedModuleDataV5{{.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_5, .statusCode = e.getCode()}, {},{},{},{},{}};
    } catch (const privmx::utils::PrivmxException& e) {
        return core::DecryptedModuleDataV5{{.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_5, .statusCode = core::ExceptionConverter::convert(e).getCode()}, {},{},{},{},{}};
    } catch (...) {
        return core::DecryptedModuleDataV5{{.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_5, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE}, {},{},{},{},{}};
    }
}

template<typename ModuleStructAsTypedObj>
auto ModuleBaseApi::extractAndDecryptModuleInternalMeta(
    ModuleStructAsTypedObj moduleObj, const core::DecryptedEncKey& encKey
) -> decltype(
    moduleObj.keyId(), moduleObj.data(), 
    core::ModuleInternalMetaV5()
) {
    auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(moduleObj.data());
    switch (versioned.versionOpt(core::ModuleDataSchema::Version::UNKNOWN)) {
        case core::ModuleDataSchema::Version::UNKNOWN:
            return core::ModuleInternalMetaV5();
        case core::ModuleDataSchema::Version::VERSION_4:
            return core::ModuleInternalMetaV5();
        case core::ModuleDataSchema::Version::VERSION_5:
            return decryptModuleDataV5(moduleObj, encKey).internalMeta;
        default:
            return core::ModuleInternalMetaV5();
    }
}

template<typename ModuleStructAsTypedObj>
auto ModuleBaseApi::getAndValidateModuleCurrentEncKey(ModuleStructAsTypedObj moduleObj) -> decltype(moduleObj.data(), moduleObj.contextId(), moduleObj.keys(), moduleObj.resourceId(), core::DecryptedEncKeyV2()) {
    auto data_entry = moduleObj.data().get(moduleObj.data().size()-1);
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    auto location {getModuleEncKeyLocation(moduleObj, moduleObj.resourceIdOpt(""))};
    keyProviderRequest.addOne(moduleObj.keys(), data_entry.keyId(), location);
    core::DecryptedEncKeyV2 ret = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(data_entry.keyId());
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
