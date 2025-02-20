/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CONTAINERPROVIDER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CONTAINERPROVIDER_HPP_

#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/utils/TypedObject.hpp>
#include <functional>

namespace privmx {
namespace endpoint {
namespace core {


template <typename ID, typename VALUE>
class ContainerProvider {
public:
    inline ContainerProvider(std::function<VALUE(ID)> getterFunction) : 
        _storage(privmx::utils::ThreadSaveMap<ID, VALUE>()), _getterFunction(getterFunction) {}

    inline virtual VALUE get(const ID& containerId)  {
        std::optional<VALUE> cachedValue = _storage.get(containerId);
        return cachedValue.has_value() ? cachedValue.value() : getFromOutsideAndUpdate(containerId);  
    }
    inline virtual void update(const ID& containerId) { getFromOutsideAndUpdate(containerId); }
    inline virtual void updateByValue(const VALUE& container) = 0;

    inline void invalidateByContainerId(const ID& containerId) {_storage.erase(containerId);}
    inline void invalidate() { _storage.clear();}
protected:
    inline VALUE getFromOutsideAndUpdate(const ID& containerId)  {
        const VALUE& container = _getterFunction(containerId);
        updateByValue(container);
        return container;
    }
    privmx::utils::ThreadSaveMap<ID, VALUE> _storage;
    std::function<VALUE(ID)> _getterFunction;
};

} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CONTAINERPROVIDER_HPP_