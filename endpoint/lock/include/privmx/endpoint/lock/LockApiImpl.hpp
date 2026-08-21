/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_LOCK_LOCKAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_LOCK_LOCKAPIIMPL_HPP_

#include <string>

#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/utils/ManualManagedClass.hpp>

#include "privmx/endpoint/lock/LockApi.hpp"
#include "privmx/endpoint/lock/ServerApi.hpp"
#include "privmx/endpoint/lock/Types.hpp"

namespace privmx {
namespace endpoint {
namespace lock {

class LockApiImpl : public privmx::utils::ManualManagedClass<LockApiImpl> {
public:
    LockApiImpl(const privfs::RpcGateway::Ptr& gateway);

    LockOperationResult lock(const std::string& resourceId, const std::string& uuid, LockLevel lockLevel);
    LockOperationResult unlock(const std::string& resourceId, const std::string& uuid, LockLevel lockLevel);
    bool checkReservedLock(const std::string& resourceId, const std::string& uuid);

private:
    static std::string lockLevelToString(LockLevel level);
    static LockLevel lockLevelFromString(const std::string& level);

    ServerApi _serverApi;
};

} // namespace lock
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_LOCK_LOCKAPIIMPL_HPP_
