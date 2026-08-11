/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/group/GroupApi.hpp"
#include "privmx/endpoint/group/VarDeserializer.hpp"
#include "privmx/endpoint/group/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace group {

/**
 * Var-typed façade over `GroupApi`, so language wrappers can call it through one dynamic entry point.
 *
 * The `METHOD` values are a **wire contract**: a wrapper sends the number, not the name. They must therefore only
 * ever be appended to, and a removed method must leave its number behind as a gap — exactly as `KvdbApiVarInterface`
 * does with its `Deleted_Function_*` placeholders. Renumbering would silently redirect a caller's request to a
 * different operation.
 */
class GroupApiVarInterface {
public:
    enum METHOD {
        Create = 0,
        CreateGroup = 1,
        UpdateGroup = 2,
        DeleteGroup = 3,
        GetGroup = 4,
        ListGroups = 5,
        GenerateNewGroupKey = 6,
        SubscribeFor = 7,
        UnsubscribeFrom = 8,
        BuildSubscriptionQuery = 9,
        // Tree-backed membership (documents/nested_groups/09-hidden-key-tree.md)
        CreateGroupWithKeyTree = 10,
        AddGroupMember = 11,
        RemoveGroupMember = 12,
    };

    GroupApiVarInterface(core::Connection connection, const core::VarSerializer& serializer)
        : _connection(std::move(connection)), _serializer(serializer) {}

    Poco::Dynamic::Var create(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createGroup(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createGroupWithKeyTree(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var addGroupMember(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var removeGroupMember(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateGroup(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var generateNewGroupKey(const Poco::Dynamic::Var& args);
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
