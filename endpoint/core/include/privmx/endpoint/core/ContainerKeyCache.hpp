/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CONTAINERKEYCACHE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CONTAINERKEYCACHE_HPP_

#include <map>
#include <mutex>
#include <shared_mutex>
#include <optional>
#include <set>
#include <vector>

#include <privmx/utils/TypedObject.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>



namespace privmx {
namespace endpoint {
namespace core {

class ContainerKeyCache {
public:
    ContainerKeyCache();
    struct ModuleKeys {
        privmx::utils::List<server::KeyEntry> keys;
        std::string currentKeyId;
        int64_t moduleSchemaVersion;
        std::string moduleResourceId;
        std::string contextId;
    };
    std::optional<ModuleKeys> getKeys(
        const std::string& moduleId, 
        const std::optional<std::set<std::string>>& requiredKeyIds = std::nullopt,
        const std::optional<int64_t> minimumRequiredModuleSchemaVersion = std::nullopt
    );

    void set(const std::string& moduleId, const ModuleKeys& newKeys);
    void clear(const std::optional<std::string>& moduleId = std::nullopt);
protected:
    
    std::optional<ModuleKeys> getModuleKeys(const std::string& moduleId);
    std::map<std::string, ModuleKeys> _storage;
    std::shared_mutex _mutex;

};

} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CONTAINERKEYCACHE_HPP_