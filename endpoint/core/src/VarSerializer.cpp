/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/VarSerializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/Validator.hpp"

using namespace privmx::endpoint::core;

// primitives

template<>
Poco::Dynamic::Var VarSerializer::serialize<int64_t>(const int64_t& val) {
    return Poco::Int64(val);
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<std::string>(const std::string& val) {
    return val;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<Buffer>(const core::Buffer& val) {
    switch (_options.binaryFormat) {
        case VarSerializer::Options::CORE_BUFFER:
            return val;
        case VarSerializer::Options::PSON_BINARYSTRING:
            return Pson::BinaryString(val.stdString());
        case VarSerializer::Options::STD_STRING_AS_BASE64:
            return utils::Base64::from(val.stdString());
        case VarSerializer::Options::STD_STRING:
            return val.stdString();
    }
    throw UnsupportedSerializerBinaryFormatException();
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<bool>(const bool& val) {
    return val;
}

// core

template<>
Poco::Dynamic::Var VarSerializer::serialize<Context>(const Context& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$Context");
    }
    obj->set("userId", serialize(val.userId));
    obj->set("contextId", serialize(val.contextId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<PagingList<Context>>(const PagingList<Context>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<core$Context>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<LibPlatformDisconnectedEvent>(const LibPlatformDisconnectedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$LibPlatformDisconnectedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("subscriptions", serialize(val.subscriptions));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<LibConnectedEvent>(const LibConnectedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$LibConnectedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("subscriptions", serialize(val.subscriptions));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<LibDisconnectedEvent>(const LibDisconnectedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$LibDisconnectedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("subscriptions", serialize(val.subscriptions));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<LibBreakEvent>(const LibBreakEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$LibBreakEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("subscriptions", serialize(val.subscriptions));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<CollectionItemChange>(const CollectionItemChange& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$CollectionItemChange");
    }
    obj->set("itemId", serialize(val.itemId));
    obj->set("action", serialize(val.action));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<CollectionChangedEventData>(const CollectionChangedEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$CollectionChangedEventData");
    }
    obj->set("moduleType", serialize(val.moduleType));
    obj->set("moduleId", serialize(val.moduleId));
    obj->set("affectedItemsCount", serialize(val.affectedItemsCount));
    obj->set("items", serialize(val.items));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<CollectionChangedEvent>(const CollectionChangedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$CollectionChangedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("subscriptions", serialize(val.subscriptions));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<ContainerPolicyWithoutItem>(const ContainerPolicyWithoutItem& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$ContainerPolicyWithoutItem");
    }
    obj->set("get", serialize(val.get));
    obj->set("update", serialize(val.update));
    obj->set("delete_", serialize(val.delete_));
    obj->set("updatePolicy", serialize(val.updatePolicy));
    obj->set("updaterCanBeRemovedFromManagers", serialize(val.updaterCanBeRemovedFromManagers));
    obj->set("ownerCanBeRemovedFromManagers", serialize(val.ownerCanBeRemovedFromManagers));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<ItemPolicy>(const ItemPolicy& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$ItemPolicy");
    }
    obj->set("get", serialize(val.get));
    obj->set("listMy", serialize(val.listMy));
    obj->set("listAll", serialize(val.listAll));
    obj->set("create", serialize(val.create));
    obj->set("update", serialize(val.update));
    obj->set("delete_", serialize(val.delete_));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<ContainerPolicy>(const ContainerPolicy& val) {
    auto valN = serialize<ContainerPolicyWithoutItem>(val);
    Poco::JSON::Object::Ptr obj = valN.extract<Poco::JSON::Object::Ptr>();
    if (_options.addType) {
        obj->set("__type", "core$ContainerPolicy");
    }
    obj->set("item", serialize(val.item));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<UserWithPubKey>(const UserWithPubKey& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$UserWithPubKey");
    }
    obj->set("userId", serialize(val.userId));
    obj->set("pubKey", serialize(val.pubKey));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<UserStatusChange>(const UserStatusChange& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$UserStatusChange");
    }
    obj->set("action", serialize(val.action));
    obj->set("timestamp", serialize(val.timestamp));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<UserInfo>(const UserInfo& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$UserInfo");
    }
    obj->set("user", serialize(val.user));
    obj->set("isActive", serialize(val.isActive));
    obj->set("lastStatusChange", serialize(val.lastStatusChange));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<PagingList<UserInfo>>(const PagingList<UserInfo>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<core$UserInfo>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<BridgeIdentity>(const BridgeIdentity& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$BridgeIdentity");
    }
    obj->set("url", serialize(val.url));
    obj->set("pubKey", serialize(val.pubKey));
    obj->set("instanceId", serialize(val.instanceId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<VerificationRequest>(const VerificationRequest& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$VerificationRequest");
    }
    obj->set("contextId", serialize(val.contextId));
    obj->set("senderId", serialize(val.senderId));
    obj->set("senderPubKey", serialize(val.senderPubKey));
    obj->set("date", serialize(val.date));
    obj->set("bridgeIdentity", serialize(val.bridgeIdentity));
    return obj;
}
