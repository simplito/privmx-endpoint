/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_SERVERTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_SERVERTYPES_HPP_

#include <string>

#include "privmx/endpoint/core/TypesMacros.hpp"
#include "privmx/endpoint/core/DynamicTypes.hpp"

namespace privmx {
namespace endpoint {
namespace core {
namespace server {

ENDPOINT_CLIENT_TYPE(ServerEvent)
    STRING_FIELD(type)
    VAR_FIELD(data)
    INT64_FIELD(timestamp)
    INT64_FIELD(version)
    LIST_FIELD(subscriptions, std::string)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(EncryptedKeyEntryDataV2, dynamic::VersionedData)
    STRING_FIELD(encryptedKey) // encrypted EncryptionKey
    STRING_FIELD(dio) // signed and encoded in base64 DataIntegrityObject
TYPE_END

ENDPOINT_SERVER_TYPE(KeyEntry)
    STRING_FIELD(keyId)
    VAR_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(KeyEntrySet)
    STRING_FIELD(user)
    STRING_FIELD(keyId)
    VAR_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(ListModel)
    STRING_FIELD(sortOrder)
    INT64_FIELD(skip)
    INT64_FIELD(limit)
    STRING_FIELD(lastId)
    STRING_FIELD(sortBy)
    VAR_FIELD(query) // JSON
TYPE_END

ENDPOINT_SERVER_TYPE(ContextInfo)
    STRING_FIELD(userId)
    STRING_FIELD(contextId)
TYPE_END

ENDPOINT_SERVER_TYPE(ContextListResult)
    LIST_FIELD(contexts, ContextInfo)
    INT64_FIELD(count)
TYPE_END

ENDPOINT_SERVER_TYPE(ContextGetModel)
    STRING_FIELD(id)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(ContextListUsersModel, core::server::ListModel)
    STRING_FIELD(contextId)
TYPE_END

ENDPOINT_CLIENT_TYPE(ContextGetResult)
    OBJECT_FIELD(context, ContextInfo)
TYPE_END

ENDPOINT_CLIENT_TYPE(UserIdentity)
    STRING_FIELD(id)
    STRING_FIELD(pub)
TYPE_END

ENDPOINT_CLIENT_TYPE(KnownKeyStatusChange)
    STRING_FIELD(action)
    INT64_FIELD(timestamp)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(UserIdentityWithStatusAndAction, UserIdentity)
    STRING_FIELD(status)
    OBJECT_FIELD(lastStatusChange, KnownKeyStatusChange)
TYPE_END

ENDPOINT_CLIENT_TYPE(ContextListUsersResult)
    LIST_FIELD(users, UserIdentityWithStatusAndAction)
    INT64_FIELD(count)
TYPE_END

ENDPOINT_CLIENT_TYPE(RpcEvent)
    STRING_FIELD(type) 
    VAR_FIELD(data)
    INT64_FIELD(version)
    INT64_FIELD(timestamp)
    LIST_FIELD(subscriptions, std::string)
TYPE_END

ENDPOINT_CLIENT_TYPE(UnsubscribeFromChannelsModel)
    LIST_FIELD(subscriptionsIds, std::string)
TYPE_END

ENDPOINT_CLIENT_TYPE(SubscribeToChannelsModel)
    LIST_FIELD(channels, std::string)
TYPE_END

ENDPOINT_CLIENT_TYPE(Subscription)
    STRING_FIELD(subscriptionId) 
    STRING_FIELD(channel) 
TYPE_END

ENDPOINT_CLIENT_TYPE(SubscribeToChannelsResult)
    LIST_FIELD(subscriptions, Subscription)
TYPE_END

ENDPOINT_SERVER_TYPE(CollectionItemChange)
    STRING_FIELD(itemId)
    STRING_FIELD(action)
TYPE_END

ENDPOINT_SERVER_TYPE(CollectionChangedEventData)
    STRING_FIELD(containerId)
    INT64_FIELD(affectedItemsCount)
    STRING_FIELD(containerType)
    LIST_FIELD(items, CollectionItemChange)
TYPE_END

} // server
} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_SERVERTYPES_HPP_
