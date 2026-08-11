/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/varinterface/GroupApiVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

std::map<GroupApiVarInterface::METHOD, Poco::Dynamic::Var (GroupApiVarInterface::*)(const Poco::Dynamic::Var&)>
    GroupApiVarInterface::methodMap = {
        {Create, &GroupApiVarInterface::create},
        {CreateGroup, &GroupApiVarInterface::createGroup},
        {UpdateGroup, &GroupApiVarInterface::updateGroup},
        {DeleteGroup, &GroupApiVarInterface::deleteGroup},
        {GetGroup, &GroupApiVarInterface::getGroup},
        {ListGroups, &GroupApiVarInterface::listGroups},
        {GenerateNewGroupKey, &GroupApiVarInterface::generateNewGroupKey},
        {SubscribeFor, &GroupApiVarInterface::subscribeFor},
        {UnsubscribeFrom, &GroupApiVarInterface::unsubscribeFrom},
        {BuildSubscriptionQuery, &GroupApiVarInterface::buildSubscriptionQuery},
        {CreateGroupWithKeyTree, &GroupApiVarInterface::createGroupWithKeyTree},
        {AddGroupMember, &GroupApiVarInterface::addGroupMember},
        {RemoveGroupMember, &GroupApiVarInterface::removeGroupMember},
};

Poco::Dynamic::Var GroupApiVarInterface::create(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _groupApi = GroupApi::create(_connection);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::createGroup(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 6);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr->get(5), "policies");
    auto result = _groupApi.createGroup(contextId, users, managers, publicMeta, privateMeta, policies);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::createGroupWithKeyTree(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 6);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr->get(5), "policies");
    auto result = _groupApi.createGroupWithKeyTree(contextId, users, managers, publicMeta, privateMeta, policies);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::addGroupMember(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 7);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto newMember = _deserializer.deserialize<core::UserWithPubKey>(argsArr->get(1), "newMember");
    auto asManager = _deserializer.deserialize<bool>(argsArr->get(2), "asManager");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(3), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(4), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(5), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(6), "privateMeta");
    _groupApi.addGroupMember(groupId, newMember, asManager, users, managers, publicMeta, privateMeta);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::removeGroupMember(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 6);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto userId = _deserializer.deserialize<std::string>(argsArr->get(1), "userId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(3), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(5), "privateMeta");
    _groupApi.removeGroupMember(groupId, userId, users, managers, publicMeta, privateMeta);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::updateGroup(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 9);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto version = _deserializer.deserialize<int64_t>(argsArr->get(5), "version");
    auto force = _deserializer.deserialize<bool>(argsArr->get(6), "force");
    auto forceGenerateNewKey = _deserializer.deserialize<bool>(argsArr->get(7), "forceGenerateNewKey");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr->get(8), "policies");
    _groupApi.updateGroup(
        groupId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies
    );
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::generateNewGroupKey(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    _groupApi.generateNewGroupKey(groupId, users, managers);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::deleteGroup(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    _groupApi.deleteGroup(groupId);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::getGroup(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto result = _groupApi.getGroup(groupId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::listGroups(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    auto result = _groupApi.listGroups(contextId, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::subscribeFor(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto subscriptionQueries = _deserializer.deserializeVector<std::string>(argsArr->get(0), "subscriptionQueries");
    auto result = _groupApi.subscribeFor(subscriptionQueries);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::unsubscribeFrom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto subscriptionIds = _deserializer.deserializeVector<std::string>(argsArr->get(0), "subscriptionIds");
    _groupApi.unsubscribeFrom(subscriptionIds);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::buildSubscriptionQuery(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto eventType = _deserializer.deserialize<group::EventType>(argsArr->get(0), "eventType");
    auto selectorType = _deserializer.deserialize<group::EventSelectorType>(argsArr->get(1), "selectorType");
    auto selectorId = _deserializer.deserialize<std::string>(argsArr->get(2), "selectorId");
    auto result = _groupApi.buildSubscriptionQuery(eventType, selectorType, selectorId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException("method=" + std::to_string((int64_t)method));
    }
    return (*this.*(it->second))(args);
}
