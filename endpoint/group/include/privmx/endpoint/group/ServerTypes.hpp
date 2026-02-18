/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_SERVERTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_SERVERTYPES_HPP_

#include <string>

#include "privmx/endpoint/core/TypesMacros.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace server {

ENDPOINT_SERVER_TYPE(GroupKeyEntry)
    STRING_FIELD(groupPubKey)
    VAR_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(GroupKeyEntrySet)
    STRING_FIELD(user)
    STRING_FIELD(groupPubKey)
    VAR_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(GroupCreateModel)
    STRING_FIELD(groupPubKey)
    STRING_FIELD(resourceId)
    STRING_FIELD(contextId)
    LIST_FIELD(users, std::string)
    LIST_FIELD(managers, std::string)
    VAR_FIELD(data)
    LIST_FIELD(keys, GroupKeyEntrySet)
TYPE_END

ENDPOINT_SERVER_TYPE(GroupUpdateModel)
    STRING_FIELD(id)
    STRING_FIELD(groupPubKey)
    STRING_FIELD(resourceId)
    LIST_FIELD(users, std::string)
    LIST_FIELD(managers, std::string)
    VAR_FIELD(data)
    LIST_FIELD(keys, GroupKeyEntrySet)
    INT64_FIELD(version)
    BOOL_FIELD(force)
TYPE_END

ENDPOINT_SERVER_TYPE(GroupDataEntry)
    STRING_FIELD(groupPubKey)
    VAR_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(GroupInfo)
    STRING_FIELD(id)
    STRING_FIELD(pubKey)
    STRING_FIELD(resourceId)
    STRING_FIELD(contextId)
    INT64_FIELD(createDate)
    STRING_FIELD(creator)
    INT64_FIELD(lastModificationDate)
    STRING_FIELD(lastModifier)
    LIST_FIELD(data, GroupDataEntry)
    LIST_FIELD(users, std::string)
    LIST_FIELD(managers, std::string)
    LIST_FIELD(keys, GroupKeyEntry)
    INT64_FIELD(version)
TYPE_END

ENDPOINT_SERVER_TYPE(GroupCreateResult)
    STRING_FIELD(groupId)
TYPE_END

ENDPOINT_SERVER_TYPE(GroupDeleteModel)
    STRING_FIELD(groupId)
TYPE_END

ENDPOINT_SERVER_TYPE(GroupGetModel)
    STRING_FIELD(groupId)
TYPE_END

ENDPOINT_SERVER_TYPE_INHERIT(GroupListModel, core::server::ListModel)
    STRING_FIELD(contextId)
TYPE_END

ENDPOINT_SERVER_TYPE(GroupGetResult)
    OBJECT_FIELD(group, GroupInfo)
TYPE_END

ENDPOINT_SERVER_TYPE(GroupListResult)
    LIST_FIELD(groups, GroupInfo)
    INT64_FIELD(count)
TYPE_END


} // server
} // group
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_SERVERTYPES_HPP_
