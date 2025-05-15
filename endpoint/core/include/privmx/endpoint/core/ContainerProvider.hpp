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

    inline ContainerInfo get(const ID& containerId)  {
        std::optional<ContainerInfo> cachedValue = _storage.get(containerId);
        ContainerInfo data = cachedValue.has_value() ? 
            cachedValue.value() : ContainerInfo{.container=_getterFunction(containerId), .status=core::DataIntegrityStatus::NotValidated};
        if(data.status == DataIntegrityStatus::NotValidated) {
            data.status = _validatorFunction(data.container) == 0 ? DataIntegrityStatus::ValidationSucceed : DataIntegrityStatus::ValidationFailed;
            updateByValueAndStatus(data);
        } 
        return data;
    }
    inline void update(const ID& containerId) {
        const VALUE& container = _getterFunction(containerId);
        updateByValueAndStatus(ContainerInfo{.container=container, .status=DataIntegrityStatus::NotValidated});
    }
    inline void updateByValue(const VALUE& container) {
        updateByValueAndStatus(ContainerInfo{.container=container, .status=DataIntegrityStatus::NotValidated});
    }
    inline void updateByValueAndStatus(const ContainerInfo& info) {
        std::shared_lock<std::shared_mutex> lock(_update_mutex);
        if(isNewerOrSameAsInStorage(info.container)) {
            _storage.set(getID(info.container), info);
        }
    }
    inline void invalidateByContainerId(const ID& containerId) {
        _storage.erase(containerId);
    }
    inline void invalidate() {
        _storage.clear();
    }
protected:
    virtual bool isNewerOrSameAsInStorage(const VALUE& container) = 0;
    virtual ID getID(const VALUE& container) = 0;
    privmx::utils::ThreadSaveMap<ID, ContainerInfo> _storage;
    std::function<VALUE(ID)> _getterFunction;
    std::function<uint32_t(VALUE)> _validatorFunction;
    std::shared_mutex _update_mutex;

};

} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CONTAINERPROVIDER_HPP_