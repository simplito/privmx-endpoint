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
#include <optional>
#include <set>
#include <shared_mutex>
#include <vector>

#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>

namespace privmx {
namespace endpoint {
namespace core {

class ContainerKeyCache {
public:
    ContainerKeyCache();
    struct CachedModuleKeys {
        std::vector<server::KeyEntry> keys;
        std::vector<server::GroupKeysEntry> groupKeys;
        std::vector<std::string> staleGroups;
        std::string currentKeyId;
        int64_t moduleSchemaVersion;
        std::string moduleResourceId;
        std::string contextId;
        int64_t moduleVersion;
        /**
         * The suite the container's policy names, or nothing when it names none — see
         * `ModuleKeys::cryptoSuite`, of which this is the cached copy.
         *
         * It is cached rather than recomputed because the cache is the only thing standing between
         * `ModuleKeys` and the module that writes with it: without this field a cache hit and a
         * cache miss on the same container hand back different write suites, and which one a write
         * gets is a matter of timing.
         */
        std::optional<CryptoSuite> cryptoSuite;
        bool forwardSecrecyEnforced = true;
    };
    std::optional<CachedModuleKeys> getKeys(
        const std::string& moduleId,
        const std::optional<std::set<std::string>>& requiredKeyIds = std::nullopt,
        const std::optional<int64_t> minimumRequiredModuleSchemaVersion = std::nullopt
    );

    void set(const std::string& moduleId, const CachedModuleKeys& newKeys, bool force = false);
    void clear(const std::optional<std::string>& moduleId = std::nullopt);

protected:
    std::optional<CachedModuleKeys> getCachedModuleKeys(const std::string& moduleId);
    std::map<std::string, CachedModuleKeys> _storage;
    std::shared_mutex _mutex;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CONTAINERKEYCACHE_HPP_