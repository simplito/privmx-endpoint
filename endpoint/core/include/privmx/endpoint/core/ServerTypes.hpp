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

#include <privmx/utils/JsonHelper.hpp>
#include "privmx/endpoint/core/DynamicTypes.hpp"

namespace privmx {
namespace endpoint {
namespace core {
namespace server {

#define SERVER_EVENT_FIELDS(F)\
    F(type,   std::string)\
    F(data,   Poco::Dynamic::Var)\
    F(timestamp, int64_t)\
    F(version, int64_t)\
    F(subscriptions, std::vector<std::string>)
JSON_STRUCT(ServerEvent_c_struct, SERVER_EVENT_FIELDS);

#define ENCRYPTED_KEY_ENTRY_DATA_V2_FIELDS(F)\
    F(encryptedKey, std::string)\
    F(dio,   std::string)
JSON_STRUCT_EXT(EncryptedKeyEntryDataV2_c_struct, dynamic::VersionedData_c_struct, ENCRYPTED_KEY_ENTRY_DATA_V2_FIELDS);

#define KEY_ENTRY_FIELDS(F)\
    F(keyId, std::string)\
    F(data, Poco::Dynamic::Var)
JSON_STRUCT(KeyEntry_c_struct, KEY_ENTRY_FIELDS);

#define KEY_ENTRY_SET_FIELDS(F)\
    F(user, std::string)\
    F(keyId, std::string)\
    F(data, Poco::Dynamic::Var)
JSON_STRUCT(KeyEntrySet_c_struct, KEY_ENTRY_SET_FIELDS);

#define LIST_MODEL_FIELDS(F)\
    F(sortOrder, std::string)\
    F(skip, int64_t)\
    F(limit, int64_t)\
    F(lastId, std::optional<std::string>)\
    F(sortBy, std::optional<std::string>)\
    F(query, std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(ListModel_c_struct, LIST_MODEL_FIELDS);

#define CONTEXT_INFO_FIELDS(F)\
    F(userId, std::string)\
    F(contextId, std::string)
JSON_STRUCT(ContextInfo_c_struct, CONTEXT_INFO_FIELDS);

#define CONTEXT_LIST_RESULT_FIELDS(F)\
    F(contexts, std::vector<ContextInfo_c_struct>)\
    F(count, int64_t)
JSON_STRUCT(ContextListResult_c_struct, CONTEXT_LIST_RESULT_FIELDS);

#define CONTEXT_GET_MODEL_FIELDS(F)\
    F(id, std::string)
JSON_STRUCT(ContextGetModel_c_struct, CONTEXT_GET_MODEL_FIELDS);

#define CONTEXT_LIST_USERS_MODEL_FIELDS(F)\
    F(contextId, std::string)
JSON_STRUCT_EXT(ContextListUsersModel_c_struct, ListModel_c_struct, CONTEXT_LIST_USERS_MODEL_FIELDS);

#define CONTEXT_GET_RESULT_FIELDS(F)\
    F(context, ContextInfo_c_struct)
JSON_STRUCT(ContextGetResult_c_struct, CONTEXT_GET_RESULT_FIELDS);

#define USER_IDENTITY_FIELDS(F)\
    F(id, std::string)\
    F(pub, std::string)
JSON_STRUCT(UserIdentity_c_struct, USER_IDENTITY_FIELDS);

#define KNOWN_KEY_STATUS_CHANGE_FIELDS(F)\
    F(action, std::string)\
    F(timestamp, int64_t)
JSON_STRUCT(KnownKeyStatusChange_c_struct, KNOWN_KEY_STATUS_CHANGE_FIELDS);

#define USER_IDENTITY_WITH_STATUS_AND_ACTION_FIELDS(F)\
    F(status,    std::string)\
    F(lastStatusChange, std::optional<KnownKeyStatusChange_c_struct>)
JSON_STRUCT_EXT(UserIdentityWithStatusAndAction_c_struct, UserIdentity_c_struct, USER_IDENTITY_WITH_STATUS_AND_ACTION_FIELDS);

#define CONTEXT_LIST_USERS_RESULT_FIELDS(F)\
    F(users, std::vector<UserIdentityWithStatusAndAction_c_struct>)\
    F(count, int64_t)
JSON_STRUCT(ContextListUsersResult_c_struct, CONTEXT_LIST_USERS_RESULT_FIELDS);

#define RPC_EVENT_FIELDS(F)\
    F(type,   std::string)\
    F(data,   Poco::Dynamic::Var)\
    F(version, int64_t)\
    F(timestamp, int64_t)\
    F(subscriptions, std::vector<std::string>)
JSON_STRUCT(RpcEvent_c_struct, RPC_EVENT_FIELDS);

#define UNSUBSCRIBE_FROM_CHANNELS_MODEL_FIELDS(F)\
    F(subscriptionsIds, std::vector<std::string>)
JSON_STRUCT(UnsubscribeFromChannelsModel_c_struct, UNSUBSCRIBE_FROM_CHANNELS_MODEL_FIELDS);

#define SUBSCRIBE_TO_CHANNELS_MODEL_FIELDS(F)\
    F(channels, std::vector<std::string>)
JSON_STRUCT(SubscribeToChannelsModel_c_struct, SUBSCRIBE_TO_CHANNELS_MODEL_FIELDS);

#define SUBSCRIPTION_FIELDS(F)\
    F(subscriptionId, std::string)\
    F(channel, std::string)
JSON_STRUCT(Subscription_c_struct, SUBSCRIPTION_FIELDS);

#define SUBSCRIBE_TO_CHANNELS_RESULT_FIELDS(F)\
    F(subscriptions, std::vector<Subscription_c_struct>)
JSON_STRUCT(SubscribeToChannelsResult_c_struct, SUBSCRIBE_TO_CHANNELS_RESULT_FIELDS);

#define CONTEXT_USER_EVENT_DATA_FIELDS(F)\
    F(contextId, std::string)\
    F(userId, std::string)\
    F(pubKey, std::string)
JSON_STRUCT(ContextUserEventData_c_struct, CONTEXT_USER_EVENT_DATA_FIELDS);

#define CONTEXT_USERS_STATUS_CHANGE_FIELDS(F)\
    F(userId, std::string)\
    F(pubKey, std::string)\
    F(action, std::string)
JSON_STRUCT(ContextUsersStatusChange_c_struct, CONTEXT_USERS_STATUS_CHANGE_FIELDS);

#define CONTEXT_USERS_STATUS_CHANGE_EVENT_DATA_FIELDS(F)\
    F(contextId, std::string)\
    F(users, std::vector<ContextUsersStatusChange_c_struct>)
JSON_STRUCT(ContextUsersStatusChangeEventData_c_struct, CONTEXT_USERS_STATUS_CHANGE_EVENT_DATA_FIELDS);

#define COLLECTION_ITEM_CHANGE_FIELDS(F)\
    F(itemId, std::string)\
    F(action, std::string)
JSON_STRUCT(CollectionItemChange_c_struct, COLLECTION_ITEM_CHANGE_FIELDS);

#define COLLECTION_CHANGED_EVENT_DATA_FIELDS(F)\
    F(containerId, std::string)\
    F(affectedItemsCount, int64_t)\
    F(containerType, std::string)\
    F(items,       std::vector<CollectionItemChange_c_struct>)
JSON_STRUCT(CollectionChangedEventData_c_struct, COLLECTION_CHANGED_EVENT_DATA_FIELDS);

} // server
} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_SERVERTYPES_HPP_
