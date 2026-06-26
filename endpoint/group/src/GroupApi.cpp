#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>

#include "privmx/endpoint/core/EventVarSerializer.hpp"
#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/group/GroupApi.hpp"
#include "privmx/endpoint/group/GroupApiImpl.hpp"
#include "privmx/endpoint/group/GroupException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

GroupApi::GroupApi() {}
GroupApi::GroupApi(const GroupApi& obj) : ExtendedPointer(obj) {}
GroupApi& GroupApi::operator=(const GroupApi& obj) {
    this->ExtendedPointer::operator=(obj);
    return *this;
}
GroupApi::GroupApi(GroupApi&& obj) : ExtendedPointer(std::move(obj)) {}
GroupApi::~GroupApi() {}

GroupApi GroupApi::create(core::Connection& connection) {
    try {
        std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
        std::shared_ptr<GroupApiImpl> impl(new GroupApiImpl(
            connectionImpl->getGateway(), connectionImpl->getUserPrivKey(), connectionImpl->getKeyProvider(),
            connectionImpl->getHost(), connectionImpl->getEventMiddleware(), connection
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
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return impl->createGroup(contextId, users, managers, publicMeta, privateMeta, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void GroupApi::updateGroup(
    const std::string& groupId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t version,
    const bool force,
    const bool forceGenerateNewKey,
    const std::optional<core::ContainerPolicy>& policies
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        impl->updateGroup(
            groupId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies
        );
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void GroupApi::generateNewGroupKey(
    const std::string& groupId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        impl->generateNewGroupKey(groupId, users, managers);
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
    core::Validator::validatePagingQuery(
        pagingQuery, {"createDate", "lastModificationDate"}, "field:pagingQuery "
    );
    try {
        return impl->listGroups(contextId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<std::string> GroupApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    try {
        return impl->subscribeFor(subscriptionQueries);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void GroupApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    try {
        return impl->unsubscribeFrom(subscriptionIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string GroupApi::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    auto impl = getImpl();
    try {
        return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
