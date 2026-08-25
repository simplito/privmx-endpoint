#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/group/GroupApi.hpp"
#include "privmx/endpoint/group/VarDeserializer.hpp"
#include "privmx/endpoint/group/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace group {

class GroupApiVarInterface {
public:
    enum METHOD {
        Create = 0,
        CreateGroupWithKeyTree = 1,
        AddGroupMember = 2,
        RemoveGroupMember = 3,
        UpdateGroup = 4,
        DeleteGroup = 5,
        GetGroup = 6,
        ListGroups = 7,
        SubscribeFor = 8,
        UnsubscribeFrom = 9,
        BuildSubscriptionQuery = 10,
    };

    GroupApiVarInterface(core::Connection connection, const core::VarSerializer& serializer)
        : _connection(std::move(connection)), _serializer(serializer) {}

    Poco::Dynamic::Var create(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createGroupWithKeyTree(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var addGroupMember(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var removeGroupMember(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateGroup(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteGroup(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getGroup(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listGroups(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeFor(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFrom(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var buildSubscriptionQuery(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

    GroupApi getApi() const { return _groupApi; }

private:
    static std::map<METHOD, Poco::Dynamic::Var (GroupApiVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::Connection _connection;
    GroupApi _groupApi;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIVARINTERFACE_HPP_
