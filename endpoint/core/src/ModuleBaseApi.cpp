/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include <type_traits>
#include <privmx/utils/Debug.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/Utils.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/ModuleBaseApi.hpp"

using namespace privmx::endpoint;
using namespace core;

ModuleBaseApi::ModuleBaseApi(
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
    const core::Connection& connection
) : _userPrivKey(userPrivKey),
    _keyProvider(keyProvider),
    _host(host),
    _eventMiddleware(eventMiddleware),
    _eventChannelManager(eventChannelManager),
    _connection(connection) {}

DecryptedEncKeyV2 ModuleBaseApi::findEncKeyByKeyId(std::unordered_map<std::string, DecryptedEncKeyV2> keys, const std::string& keyId) {
    for (auto key : keys) {
        if (keyId == key.first) {
            return key.second;
        }
    }
    throw UnknownModuleEncryptionKeyException();
}

core::DecryptedEncKeyV2 ModuleBaseApi::getAndValidateModuleCurrentEncKey(ModuleKeys moduleKeys) {
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    auto location = core::EncKeyLocation{.contextId=moduleKeys.contextId, .resourceId=moduleKeys.moduleResourceId};
    keyProviderRequest.addOne(moduleKeys.keys, moduleKeys.currentKeyId, location);
    return _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(moduleKeys.currentKeyId);
}

ModuleKeys ModuleBaseApi::getModuleKeys(
    const std::string& moduleId, 
    const std::optional<std::set<std::string>>& keyIds, 
    const std::optional<int64_t>& minimumSchemaVersion
) {
    auto keys = _keyCache.getKeys(moduleId, keyIds, minimumSchemaVersion);
    // if cache don't have decryption keys 
    if(!keys.has_value()) {
        return getNewModuleKeysAndUpdateCache(moduleId);
    }
    return convertContainerKeyCacheModuleKeysToModuleApiFormat(keys.value());
}

void ModuleBaseApi::setNewModuleKeysInCache(const std::string& moduleId, const ModuleKeys& newKeys, int64_t moduleVersion) {
    auto keys = convertModuleKeysToContainerKeyCacheFormat(newKeys, moduleVersion);
    _keyCache.set(moduleId, keys);
}

void ModuleBaseApi::invalidateModuleKeysInCache(const std::optional<std::string>& moduleId) {
    _keyCache.clear(moduleId);
}

ModuleKeys ModuleBaseApi::getNewModuleKeysAndUpdateCache(const std::string& moduleId) {
    // get newest module
    PRIVMX_DEBUG("PlatformModule", "getNewModuleKeysAndUpdateCache")
    auto moduleKeys = getModuleKeysAndVersionFromServer(moduleId);
    auto keys = convertModuleKeysToContainerKeyCacheFormat(moduleKeys.first, moduleKeys.second);
    _keyCache.set(moduleId, keys);
    return moduleKeys.first;
}

core::ContainerKeyCache::CachedModuleKeys ModuleBaseApi::convertModuleKeysToContainerKeyCacheFormat(const ModuleKeys& moduleKeys, int64_t moduleVersion) {
    return core::ContainerKeyCache::CachedModuleKeys{
        .keys=moduleKeys.keys,
        .currentKeyId=moduleKeys.currentKeyId,
        .moduleSchemaVersion=moduleKeys.moduleSchemaVersion,
        .moduleResourceId=moduleKeys.moduleResourceId,
        .contextId = moduleKeys.contextId
    };
}

ModuleKeys ModuleBaseApi::convertContainerKeyCacheModuleKeysToModuleApiFormat(const core::ContainerKeyCache::CachedModuleKeys& moduleKeys) {
    return ModuleKeys{
        .keys=moduleKeys.keys,
        .currentKeyId=moduleKeys.currentKeyId,
        .moduleSchemaVersion=moduleKeys.moduleSchemaVersion,
        .moduleResourceId=moduleKeys.moduleResourceId,
        .contextId = moduleKeys.contextId
    };
}