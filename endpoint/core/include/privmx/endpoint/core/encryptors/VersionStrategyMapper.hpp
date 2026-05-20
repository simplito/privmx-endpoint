/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_VERSIONSTRATEGYMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_VERSIONSTRATEGYMAPPER_HPP_

#include <cstdint>
#include <memory>
#include <unordered_map>

#include "privmx/endpoint/core/encryptors/IDataSchemaStrategy.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<typename TServerModel, typename TDomainObject>
class VersionStrategyMapper {
public:
    using Strategy = IDataSchemaStrategy<TServerModel, TDomainObject>;
    using StrategyPtr = std::shared_ptr<Strategy>;

    void registerStrategy(int64_t version, StrategyPtr strategy) { _strategies[version] = std::move(strategy); }

    StrategyPtr getStrategy(int64_t version) const {
        auto it = _strategies.find(version);
        if (it == _strategies.end())
            return nullptr;
        return it->second;
    }

private:
    std::unordered_map<int64_t, StrategyPtr> _strategies;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_VERSIONSTRATEGYMAPPER_HPP_
