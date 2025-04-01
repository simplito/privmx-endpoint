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

enum DataIntegrityStatus {
    NotValidated, 
    ValidationFailed,
    ValidationSucceed
};


template <typename ID, typename VALUE>
class ContainerProvider {
public:
    struct ContainerInfo {
        VALUE container;
        DataIntegrityStatus status;
    };
    inline ContainerProvider(std::function<VALUE(ID)> getterFunction, std::function<uint32_t(VALUE)> validatorFunction) : 
        _storage(privmx::utils::ThreadSaveMap<ID, ContainerInfo>()), _getterFunction(getterFunction), _validatorFunction(validatorFunction) {}

    inline virtual ContainerInfo get(const ID& containerId)  {
        std::optional<ContainerInfo> cachedValue = _storage.get(containerId);
        ContainerInfo data = cachedValue.has_value() ? cachedValue.value() : getFromOutsideAndUpdate(containerId);
        if(data.status == DataIntegrityStatus::NotValidated) {
            data.status = _validatorFunction(data.container) == 0 ? DataIntegrityStatus::ValidationSucceed : DataIntegrityStatus::ValidationFailed;
        } 
        return data;
    }
    inline virtual void update(const ID& containerId) { getFromOutsideAndUpdate(containerId); }
    inline virtual void updateByValue(const VALUE& container) = 0;
    inline void updateDataIntegrityStatus(const ID& containerId, const DataIntegrityStatus& status) {
        std::optional<ContainerInfo> container = _storage.get(containerId);
        if(container.has_value()) {
            container.value().status = status;
        }
    }

    inline void invalidateByContainerId(const ID& containerId) {_storage.erase(containerId);}
    inline void invalidate() { _storage.clear();}
protected:
    
    inline ContainerInfo getFromOutsideAndUpdate(const ID& containerId)  {
        const VALUE& container = _getterFunction(containerId);
        updateByValue(container);
        std::optional<ContainerInfo> afterUpdate = _storage.get(containerId);
        return ContainerInfo{
            .container = container, 
            .status = afterUpdate.has_value() ? afterUpdate.value().status : DataIntegrityStatus::NotValidated
        };
    }
    privmx::utils::ThreadSaveMap<ID, ContainerInfo> _storage;
    std::function<VALUE(ID)> _getterFunction;
    std::function<uint32_t(VALUE)> _validatorFunction;
};

} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CONTAINERPROVIDER_HPP_