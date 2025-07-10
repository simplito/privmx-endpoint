/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/ContainerKeyCache.hpp>

using namespace privmx::endpoint::core;

ContainerKeyCache::ContainerKeyCache() : _storage(std::map<std::string, ContainerKeyCache::CachedModuleKeys>()) {}

std::optional<ContainerKeyCache::CachedModuleKeys> ContainerKeyCache::getKeys(
    const std::string& moduleId, 
    const std::optional<std::set<std::string>>& requiredKeyIds,
    const std::optional<int64_t> minimumRequiredModuleSchemaVersion
) {
    auto moduleKeys = getCachedModuleKeys(moduleId);
    if(!moduleKeys.has_value()) {
        return std::nullopt;
    }
    if(requiredKeyIds.has_value()) {
        std::set<std::string> keyIds = requiredKeyIds.value();
        utils::List<server::KeyEntry> keysToDecrypt = utils::TypedObjectFactory::createNewList<server::KeyEntry>();
        for (auto key : moduleKeys->keys) {
            if(std::find(keyIds.begin(), keyIds.end(), key.keyId()) != keyIds.end()) {
                keyIds.erase(key.keyId());
            }
        }
        if(keyIds.size() != 0) {
            return std::nullopt;
        }
    }
    if(requiredKeyIds.has_value() && moduleKeys->moduleSchemaVersion < minimumRequiredModuleSchemaVersion) {
        return std::nullopt;
    }  
    return moduleKeys;
}

void ContainerKeyCache::set(const std::string& moduleId, const CachedModuleKeys& newKeys, bool force) {
    std::unique_lock<std::shared_mutex> lock(_mutex);
    auto moduleKeys = getCachedModuleKeys(moduleId);
    if(moduleKeys.has_value() && moduleKeys->moduleVersion > newKeys.moduleVersion) {
        // nothin to change version is older then version in cache
        return;
    }
    _storage.insert_or_assign(
        moduleId,
        newKeys
    );
}

void ContainerKeyCache::clear(const std::optional<std::string>& moduleId) {
    std::unique_lock<std::shared_mutex> lock(_mutex);
    if(!moduleId.has_value()) {
        _storage.clear();
        return;
    }
    _storage.erase(moduleId.value());
}

std::optional<ContainerKeyCache::CachedModuleKeys> ContainerKeyCache::getCachedModuleKeys(const std::string& moduleId) {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    auto moduleKeys = _storage.find(moduleId);
    if (moduleKeys == _storage.end()) {
        return std::nullopt;
    }
    return moduleKeys->second;
}
