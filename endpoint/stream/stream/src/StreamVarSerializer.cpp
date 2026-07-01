/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/StreamVarSerializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::TurnCredentials>(const stream::TurnCredentials& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$TurnCredentials");
    }
    obj->set("url", serialize(val.url));
    obj->set("username", serialize(val.username));
    obj->set("password", serialize(val.password));
    obj->set("expirationTime", serialize(val.expirationTime));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::Stream>(const stream::Stream& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$Stream");
    }
    obj->set("streamId", serialize(val.streamId));
    obj->set("userId", serialize(val.userId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<stream::StreamRoom>>(
    const core::PagingList<stream::StreamRoom>& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<stream$StreamRoom>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamRoom>(const stream::StreamRoom& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamRoom");
    }
    obj->set("streamRoomId", serialize(val.streamRoomId));
    obj->set("contextId", serialize(val.contextId));
    obj->set("createDate", serialize(val.createDate));
    obj->set("creator", serialize(val.creator));
    obj->set("lastModificationDate", serialize(val.lastModificationDate));
    obj->set("lastModifier", serialize(val.lastModifier));
    obj->set("users", serialize(val.users));
    obj->set("managers", serialize(val.managers));
    obj->set("version", serialize(val.version));
    obj->set("publicMeta", serialize(val.publicMeta));
    obj->set("privateMeta", serialize(val.privateMeta));
    obj->set("policy", serialize(val.policy));
    obj->set("statusCode", serialize(val.statusCode));
    obj->set("schemaVersion", serialize(val.schemaVersion));
    obj->set("state", serialize(val.state));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamRoomDeletedEventData>(
    const stream::StreamRoomDeletedEventData& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamRoomDeletedEventData");
    }
    obj->set("streamRoomId", serialize(val.streamRoomId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamRoomParticipantEventData>(
    const stream::StreamRoomParticipantEventData& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamRoomParticipantEventData");
    }
    obj->set("streamRoomId", serialize(val.streamRoomId));
    obj->set("userId", serialize(val.userId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamSubscriptionEventData>(
    const stream::StreamSubscriptionEventData& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamSubscriptionEventData");
    }
    obj->set("streamRoomId", serialize(val.streamRoomId));
    obj->set("userId", serialize(val.userId));
    Poco::JSON::Array::Ptr subsArr = new Poco::JSON::Array();
    for (const auto& sub : val.subscriptions) {
        subsArr->add(serialize<stream::StreamSubscription>(sub));
    }
    obj->set("subscriptions", subsArr);
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamRoomCreatedEvent>(const stream::StreamRoomCreatedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamRoomCreatedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamRoomUpdatedEvent>(const stream::StreamRoomUpdatedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamRoomUpdatedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamRoomDeletedEvent>(const stream::StreamRoomDeletedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamRoomDeletedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamPublishedEvent>(const stream::StreamPublishedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamPublishedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamPublishedEventData>(
    const stream::StreamPublishedEventData& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamPublishedEventData");
    }
    obj->set("streamRoomId", serialize(val.streamRoomId));
    obj->set("stream", serialize(val.stream));
    obj->set("userId", serialize(val.userId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamUpdatedEvent>(const stream::StreamUpdatedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamUpdatedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamUpdatedEventData>(const stream::StreamUpdatedEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamUpdatedEventData");
    }
    obj->set("streamRoomId", serialize(val.streamRoomId));
    obj->set("streamId", serialize(val.streamId));
    obj->set("userId", serialize(val.userId));
    obj->set("tracksAdded", serialize<stream::StreamTrackInfo>(val.tracksAdded));
    obj->set("tracksRemoved", serialize<stream::StreamTrackInfo>(val.tracksRemoved));
    obj->set("tracksModified", serialize<stream::StreamTrackModificationPair>(val.tracksModified));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamTrackModificationPair>(
    const stream::StreamTrackModificationPair& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamTrackModificationPair");
    }
    obj->set("before", serialize(val.before));
    obj->set("after", serialize(val.after));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamPublishResult>(const stream::StreamPublishResult& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamPublishResult");
    }
    if (val.data.has_value()) {
        obj->set("data", serialize(val.data.value()));
    }
    obj->set("published", serialize(val.published));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamRoomJoinedEvent>(const stream::StreamRoomJoinedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamRoomJoinedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamUnpublishedEventData>(
    const stream::StreamUnpublishedEventData& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamUnpublishedEventData");
    }
    obj->set("streamRoomId", serialize(val.streamRoomId));
    obj->set("streamId", serialize(val.streamId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamUnpublishedEvent>(const stream::StreamUnpublishedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamUnpublishedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamRoomLeftEvent>(const stream::StreamRoomLeftEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamRoomLeftEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamSubscribedEvent>(const stream::StreamSubscribedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamSubscribedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamUnsubscribedEvent>(
    const stream::StreamUnsubscribedEvent& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamUnsubscribedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamTrackInfo>(const stream::StreamTrackInfo& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamTrackInfo");
    }
    obj->set("type", serialize(val.type));
    obj->set("mindex", serialize(val.mindex));
    obj->set("mid", serialize(val.mid));
    obj->set("disabled", serialize(val.disabled));
    if (val.codec.has_value()) {
        obj->set("codec", serialize(val.codec.value()));
    }
    if (val.description.has_value()) {
        obj->set("description", serialize(val.description.value()));
    }
    obj->set("moderated", serialize(val.moderated));
    obj->set("simulcast", serialize(val.simulcast));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamInfo>(const stream::StreamInfo& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamInfo");
    }

    obj->set("id", serialize(val.id));
    obj->set("userId", serialize(val.userId));
    if (val.metadata.has_value()) {
        obj->set("metadata", serialize(val.metadata.value()));
    }
    obj->set("dummy", serialize(val.dummy));
    Poco::JSON::Array::Ptr tracksArr = new Poco::JSON::Array();
    for (auto track : val.tracks) {
        tracksArr->add(serialize<stream::StreamTrackInfo>(track));
    }
    obj->set("tracks", tracksArr);
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::SdpWithTypeModel>(const stream::SdpWithTypeModel& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$SdpWithTypeModel");
    }
    obj->set("sdp", serialize(val.sdp));
    obj->set("type", serialize(val.type));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::Key>(const stream::Key& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$Key");
    }
    obj->set("keyId", serialize(val.keyId));
    obj->set("key", serialize(val.key));
    obj->set("type", serialize(val.type));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::KeyType>(const stream::KeyType& val) {

    return Poco::Dynamic::Var(static_cast<int>(val));
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamSubscription>(const stream::StreamSubscription& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamSubscription");
    }
    obj->set("streamId", serialize(val.streamId));
    if (val.streamTrackId.has_value()) {
        obj->set("streamTrackId", serialize(val.streamTrackId));
    }
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamSubscriber>(const stream::StreamSubscriber& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamSubscriber");
    }
    obj->set("userId", serialize(val.userId));
    obj->set("subscriptions", serialize<stream::StreamSubscription>(val.subscriptions));
    obj->set("publishedStream", serialize(val.publishedStream));
    return obj;
}