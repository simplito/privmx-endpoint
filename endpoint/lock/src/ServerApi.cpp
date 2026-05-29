/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/lock/ServerApi.hpp"

using namespace privmx::endpoint::lock;

ServerApi::ServerApi(privmx::privfs::RpcGateway::Ptr gateway) : _gateway(gateway) {}

server::LockOperationResult ServerApi::lockLock(server::LockLockModel model) {
    return request<server::LockOperationResult>("lockLock", model.toJSON());
}

server::LockOperationResult ServerApi::lockUnlock(server::LockUnlockModel model) {
    return request<server::LockOperationResult>("lockUnlock", model.toJSON());
}

server::LockCheckReservedLockResult ServerApi::lockCheckReservedLock(server::LockCheckReservedLockModel model) {
    return request<server::LockCheckReservedLockResult>("lockCheckReservedLock", model.toJSON());
}

template<class T>
T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return T::fromJSON(_gateway->request("lock." + method, params));
}
