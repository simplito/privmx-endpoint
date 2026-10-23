/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/Exception.hpp>

#include "privmx/endpoint/lock/LockApi.hpp"
#include "privmx/endpoint/lock/LockApiImpl.hpp"
#include "privmx/endpoint/lock/LockException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::lock;

LockApi::LockApi() {}
LockApi::LockApi(const LockApi& obj) : BaseApiClass(obj) {}
LockApi& LockApi::operator=(const LockApi& obj) {
    this->BaseApiClass::operator=(obj);
    return *this;
}
LockApi::LockApi(LockApi&& obj) : BaseApiClass(std::move(obj)) {}
LockApi::~LockApi() {}

LockApi LockApi::create(core::Connection& connection) {
    std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
    std::shared_ptr<LockApiImpl> impl(new LockApiImpl(connectionImpl->getGateway()));
    return LockApi(impl);
}

LockApi::LockApi(const std::shared_ptr<LockApiImpl>& impl) : BaseApiClass(impl) {}

LockOperationResult LockApi::lock(const std::string& resourceId, const std::string& uuid, LockLevel lockLevel) {
    return getImpl()->lock(resourceId, uuid, lockLevel);
}

LockOperationResult LockApi::unlock(const std::string& resourceId, const std::string& uuid, LockLevel lockLevel) {
    return getImpl()->unlock(resourceId, uuid, lockLevel);
}

bool LockApi::checkReservedLock(const std::string& resourceId, const std::string& uuid) {
    return getImpl()->checkReservedLock(resourceId, uuid);
}
