/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_VARSERIALIZATION_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_VARSERIALIZATION_HPP_

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/core/VarDeserializer.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"
#include "privmx/endpoint/core/VarSerializationMacros.hpp"

namespace privmx {
namespace endpoint {
namespace core {

// ---------------------------------------------------------------------------
// Standard types — field layout matches struct, no custom __type string
// ---------------------------------------------------------------------------

VAR_DEFINE_TYPE(UserWithPubKey, userId, pubKey)
VAR_DEFINE_TYPE(Context, userId, contextId)
VAR_DEFINE_TYPE(CollectionItemChange, itemId, action)
VAR_DEFINE_TYPE(CollectionChangedEventData, moduleType, moduleId, affectedItemsCount, items)
VAR_DEFINE_TYPE(ContextUserEventData, contextId, user)
VAR_DEFINE_TYPE(UserWithAction, user, action)
VAR_DEFINE_TYPE(ContainerPolicyWithoutItem, get, update, delete_, updatePolicy, updaterCanBeRemovedFromManagers, ownerCanBeRemovedFromManagers)
VAR_DEFINE_TYPE(ItemPolicy, get, listMy, listAll, create, update, delete_)
VAR_DEFINE_TYPE(UserStatusChange, action, timestamp)
VAR_DEFINE_TYPE(UserInfo, user, isActive, lastStatusChange)
VAR_DEFINE_TYPE(BridgeIdentity, url, pubKey, instanceId)
VAR_DEFINE_TYPE(VerificationRequest, contextId, senderId, senderPubKey, date, bridgeIdentity)
VAR_DEFINE_TYPE(PagingQuery, skip, limit, sortOrder, lastId, sortBy, queryAsJson)
VAR_DEFINE_TYPE(PKIVerificationOptions, bridgePubKey, bridgeInstanceId)

VAR_DEFINE_TYPE(PagingList<Context>, totalAvailable, readItems) // FIXME: custom __type
VAR_DEFINE_TYPE(PagingList<UserInfo>, totalAvailable, readItems) // FIXME: custom __type

// ---------------------------------------------------------------------------
// PagingList<T> — custom __type strings
// ---------------------------------------------------------------------------

// template<>
// inline Poco::Dynamic::Var VarSerializer::serialize<PagingList<Context>>(const PagingList<Context>& val) {
//     Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
//     if (_options.addType) { obj->set("__type", "core$PagingList<core$Context>"); }
//     obj->set("totalAvailable", serialize(val.totalAvailable));
//     obj->set("readItems", serialize(val.readItems));
//     return obj;
// }

// template<>
// inline Poco::Dynamic::Var VarSerializer::serialize<PagingList<UserInfo>>(const PagingList<UserInfo>& val) {
//     Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
//     if (_options.addType) { obj->set("__type", "core$PagingList<core$UserInfo>"); }
//     obj->set("totalAvailable", serialize(val.totalAvailable));
//     obj->set("readItems", serialize(val.readItems));
//     return obj;
// }

// ---------------------------------------------------------------------------
// Event types — delegate to serializeBase / serializeBaseWithData
// ---------------------------------------------------------------------------

template<>
inline Poco::Dynamic::Var VarSerializer::serialize<LibPlatformDisconnectedEvent>(const LibPlatformDisconnectedEvent& val) {
    return serializeBase<Event>(val, "core$LibPlatformDisconnectedEvent");
}

template<>
inline Poco::Dynamic::Var VarSerializer::serialize<LibConnectedEvent>(const LibConnectedEvent& val) {
    return serializeBase<Event>(val, "core$LibConnectedEvent");
}

template<>
inline Poco::Dynamic::Var VarSerializer::serialize<LibDisconnectedEvent>(const LibDisconnectedEvent& val) {
    return serializeBase<Event>(val, "core$LibDisconnectedEvent");
}

template<>
inline Poco::Dynamic::Var VarSerializer::serialize<LibBreakEvent>(const LibBreakEvent& val) {
    return serializeBase<Event>(val, "core$LibBreakEvent");
}

template<>
inline Poco::Dynamic::Var VarSerializer::serialize<ContextUsersStatusChangedEventData>(const ContextUsersStatusChangedEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) { obj->set("__type", "core$ContextUsersStatusChangeData"); }
    obj->set("contextId", serialize(val.contextId));
    obj->set("users", serialize(val.users));
    return obj;
}

template<>
inline Poco::Dynamic::Var VarSerializer::serialize<ContextUserAddedEvent>(const ContextUserAddedEvent& val) {
    return serializeBaseWithData<Event>(val, "core$ContextUserAddedEvent");
}

template<>
inline Poco::Dynamic::Var VarSerializer::serialize<ContextUserRemovedEvent>(const ContextUserRemovedEvent& val) {
    return serializeBaseWithData<Event>(val, "core$ContextUserRemovedEvent");
}

template<>
inline Poco::Dynamic::Var VarSerializer::serialize<ContextUsersStatusChangedEvent>(const ContextUsersStatusChangedEvent& val) {
    return serializeBaseWithData<Event>(val, "core$ContextUsersStatusChangedEvent");
}

template<>
inline Poco::Dynamic::Var VarSerializer::serialize<CollectionChangedEvent>(const CollectionChangedEvent& val) {
    return serializeBaseWithData<Event>(val, "core$CollectionChangedEvent");
}

// ---------------------------------------------------------------------------
// ContainerPolicy — serializer extends ContainerPolicyWithoutItem
// ---------------------------------------------------------------------------

template<>
inline Poco::Dynamic::Var VarSerializer::serialize<ContainerPolicy>(const ContainerPolicy& val) {
    auto varN = serialize<ContainerPolicyWithoutItem>(val);
    Poco::JSON::Object::Ptr obj = varN.extract<Poco::JSON::Object::Ptr>();
    if (_options.addType) { obj->set("__type", "core$ContainerPolicy"); }
    obj->set("item", serialize(val.item));
    return obj;
}

// ContainerPolicy deserializer — cannot reuse VAR_DEFINE_TYPE (inherits WithoutItem fields)
template<>
inline void VarDeserializer::deserialize<ContainerPolicy>(
        const Poco::Dynamic::Var& val, const std::string& name, ContainerPolicy& out) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    deserialize(obj->get("get"), name + ".get", out.get);
    deserialize(obj->get("update"), name + ".update", out.update);
    deserialize(obj->get("delete_"), name + ".delete_", out.delete_);
    deserialize(obj->get("updatePolicy"), name + ".updatePolicy", out.updatePolicy);
    deserialize(obj->get("updaterCanBeRemovedFromManagers"), name + ".updaterCanBeRemovedFromManagers", out.updaterCanBeRemovedFromManagers);
    deserialize(obj->get("ownerCanBeRemovedFromManagers"), name + ".ownerCanBeRemovedFromManagers", out.ownerCanBeRemovedFromManagers);
    deserialize(obj->get("item"), name + ".item", out.item);
}

// ---------------------------------------------------------------------------
// Enum deserializers — switch on integer value
// ---------------------------------------------------------------------------

template<>
inline void VarDeserializer::deserialize<EventType>(
        const Poco::Dynamic::Var& val, const std::string& name, EventType& out) {
    switch (val.convert<int64_t>()) {
        case core::EventType::USER_ADD:    out = core::EventType::USER_ADD;    return;
        case core::EventType::USER_REMOVE: out = core::EventType::USER_REMOVE; return;
        case core::EventType::USER_STATUS: out = core::EventType::USER_STATUS; return;
    }
    throw InvalidParamsException(name + " | Unknown thread::EventType value, received " + std::to_string(val.convert<int64_t>()));
}

template<>
inline void VarDeserializer::deserialize<EventSelectorType>(
        const Poco::Dynamic::Var& val, const std::string& name, EventSelectorType& out) {
    switch (val.convert<int64_t>()) {
        case core::EventSelectorType::CONTEXT_ID: out = core::EventSelectorType::CONTEXT_ID; return;
    }
    throw InvalidParamsException(name + " | Unknown thread::EventSelectorType value, received " + std::to_string(val.convert<int64_t>()));
}

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_VARSERIALIZATION_HPP_
