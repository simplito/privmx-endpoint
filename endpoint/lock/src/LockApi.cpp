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
#include <privmx/endpoint/core/ExceptionConverter.hpp>

#include "privmx/endpoint/lock/LockApi.hpp"
#include "privmx/endpoint/lock/LockApiImpl.hpp"
#include "privmx/endpoint/lock/LockException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::lock;

LockApi::LockApi() {}
LockApi::LockApi(const LockApi& obj) : ExtendedPointer(obj) {}
LockApi& LockApi::operator=(const LockApi& obj) {
    this->ExtendedPointer::operator=(obj);
    return *this;
}
LockApi::LockApi(LockApi&& obj) : ExtendedPointer(std::move(obj)) {}
LockApi::~LockApi() {}

LockApi LockApi::create(core::Connection& connection) {
    try {
        std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
        std::shared_ptr<LockApiImpl> impl(new LockApiImpl(connectionImpl->getGateway()));
        impl->attach(impl);
        return LockApi(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

LockApi::LockApi(const std::shared_ptr<LockApiImpl>& impl) : ExtendedPointer(impl) {}

LockOperationResult LockApi::lock(const std::string& resourceId, const std::string& uuid, LockLevel lockLevel) {
    auto impl = getImpl();
    try {
        return impl->lock(resourceId, uuid, lockLevel);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

LockOperationResult LockApi::unlock(const std::string& resourceId, const std::string& uuid, LockLevel lockLevel) {
    auto impl = getImpl();
    try {
        return impl->unlock(resourceId, uuid, lockLevel);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool LockApi::checkReservedLock(const std::string& resourceId, const std::string& uuid) {
    auto impl = getImpl();
    try {
        return impl->checkReservedLock(resourceId, uuid);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
