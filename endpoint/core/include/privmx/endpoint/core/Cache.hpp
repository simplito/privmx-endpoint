/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CACHE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CACHE_HPP_

#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/utils/TypedObject.hpp>
#include <functional>

namespace privmx {
namespace endpoint {
namespace core {


template <typename ID, typename VALUE>
class Cache {
public:
    inline Cache(std::function<VALUE(ID)> getterFunction) : 
        _storage(privmx::utils::ThreadSaveMap<ID, VALUE>()), _getterFunction(getterFunction) {}

    inline virtual VALUE get(const ID& id, bool force = true)  {
        if(force) {
            return getFromOutsideAndUpdate(id);
        }
        std::optional<VALUE> cachedValue = _storage.get(id);
        return cachedValue.has_value() ? cachedValue.value() : getFromOutsideAndUpdate(id);  
    }

    inline virtual void update(const ID& id, const VALUE& value) { _storage.set(id, value); }

    inline void remove(const ID& id) {_storage.erase(id);}

    inline void reset() { _storage.clear();}
protected:
    inline VALUE getFromOutsideAndUpdate(const ID& id)  {
        const VALUE& value = _getterFunction(id);
        update(id, value);
        return value;
    }
    privmx::utils::ThreadSaveMap<ID, VALUE> _storage;
    std::function<VALUE(ID)> _getterFunction;
};

} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CACHE_HPP_