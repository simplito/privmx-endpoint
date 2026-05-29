/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_LOCK_SERVER_API_HPP_
#define _PRIVMXLIB_ENDPOINT_LOCK_SERVER_API_HPP_

#include <privmx/privfs/gateway/RpcGateway.hpp>

#include "privmx/endpoint/lock/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace lock {

class ServerApi {
public:
    ServerApi(privmx::privfs::RpcGateway::Ptr gateway);

    server::LockOperationResult lockLock(server::LockLockModel model);
    server::LockOperationResult lockUnlock(server::LockUnlockModel model);
    server::LockCheckReservedLockResult lockCheckReservedLock(server::LockCheckReservedLockModel model);

private:
    template<typename T>
    T request(const std::string& method, Poco::JSON::Object::Ptr params);

    privfs::RpcGateway::Ptr _gateway;
};

} // namespace lock
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_LOCK_SERVER_API_HPP_
