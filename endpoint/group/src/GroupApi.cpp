/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>

#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/group/GroupApi.hpp"
#include "privmx/endpoint/group/GroupApiImpl.hpp"
#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/core/EventVarSerializer.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;


GroupApi::GroupApi() {};
GroupApi::GroupApi(const GroupApi& obj): ExtendedPointer(obj) {};
GroupApi& GroupApi::operator=(const GroupApi& obj) {
    this->ExtendedPointer::operator=(obj);
    return *this;
};
GroupApi::GroupApi(GroupApi&& obj): ExtendedPointer(std::move(obj)) {};
GroupApi::~GroupApi() {}

GroupApi GroupApi::create(core::Connection& connection) {
    try {
        std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
        std::shared_ptr<GroupApiImpl> impl(new GroupApiImpl(
            connectionImpl->getGateway(),
            connectionImpl->getUserPrivKey(),
            connectionImpl->getKeyProvider(),
            connectionImpl->getHost(),
            connectionImpl->getEventMiddleware(),
            connection
        ));
        impl->attach(impl);
        return GroupApi(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

GroupApi::GroupApi(const std::shared_ptr<GroupApiImpl>& impl) : ExtendedPointer(impl) {}

std::string GroupApi::createGroup(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return impl->createGroup(contextId, users, managers, publicMeta, privateMeta);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void GroupApi::updateGroup(
    const std::string& groupId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta, 
    const int64_t version, 
    const bool force
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    try {
        impl->updateGroup(groupId, publicMeta, privateMeta, version, force);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void GroupApi::modifyGroupMembers(const std::string& groupId,
        const std::vector<core::UserWithPubKey>& usersToAddOrUpdate, const std::vector<std::string>& usersToRemove,
        const std::vector<core::UserWithPubKey>& managersToAddOrUpdate, const std::vector<std::string>& managersToRemove
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    try {
        impl->modifyGroupMembers(groupId, usersToAddOrUpdate, usersToRemove, managersToAddOrUpdate, managersToRemove);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void GroupApi::deleteGroup(const std::string& groupId) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    try {
        return impl->deleteGroup(groupId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Group GroupApi::getGroup(const std::string& groupId) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    try {
        return impl->getGroup(groupId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<Group> GroupApi::listGroups(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(pagingQuery, {"createDate", "lastModificationDate", "lastMsgDate"}, "field:pagingQuery ");
    try {
        return impl->listGroups(contextId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
