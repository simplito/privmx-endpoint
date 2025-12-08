/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_LOCKSETLOGIC_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_LOCKSETLOGIC_HPP_

#include <memory>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/search/DynamicTypes.hpp"
#include "privmx/endpoint/search/SearchTypes.hpp"

namespace privmx {
namespace endpoint {
namespace search {

class LockSetLogic
{
public:
    static constexpr int64_t TIMEOUT_DELTA = 60 * 1000;

    struct LockResult
    {
        bool success;
        bool save;
    };

    LockSetLogic();
    void deserializeAndSetLockSet(const core::Buffer& buffer);
    void setEmptyLockSet();
    core::Buffer getAndSerializeLockSet();
    LockResult lock(LockLevel level);
    LockResult unlock(LockLevel level);
    bool checkReservedLock();

private:
    std::string generateId();
    void deleteTimeoutedLocks();
    void deleteMyLocks();
    dynamic::Lock getMyLock();
    dynamic::Lock createMyLock(LockLevel level);

    std::string _lockId;
    dynamic::LockSet _lockSet;
};

}  // namespace search
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SEARCH_LOCKSETLOGIC_HPP_
