/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_SELF_MANAGED_CLASS_
#define _PRIVMXLIB_UTILS_SELF_MANAGED_CLASS_

#include <iostream>
#include <memory>
#include <mutex>
#include <atomic>

namespace privmx {
namespace utils {

template <typename T>
class ManualManagedClass {
public:
    inline void attach() {
        std::unique_lock lock(_selfRefMutex); _attachObjectCounter++;
    }
    inline void attach(const std::shared_ptr<T>& newSelfRef) {
        std::unique_lock lock(_selfRefMutex); _attachObjectCounter++; _selfRef = newSelfRef;
    }
    inline void detach() {
        std::unique_lock lock(_selfRefMutex); _attachObjectCounter--; if(_attachObjectCounter.load() == 0) _selfRef.reset();
     }
    inline void cleanup() {std::unique_lock lock(_selfRefMutex); _attachObjectCounter.store(0); _selfRef.reset();}
private:
    std::atomic_int64_t _attachObjectCounter = 0;
    std::mutex _selfRefMutex;
    std::shared_ptr<T> _selfRef;
};

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_SELF_MANAGED_CLASS_
