/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/StreamWebRTCVarSerializer.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamConnectionStateChangedEventData>(
    const stream::StreamConnectionStateChangedEventData& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamConnectionStateChangedEventData");
    }
    obj->set("streamRoomId", serialize(val.streamRoomId));
    obj->set("state", serialize(static_cast<int64_t>(val.state)));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamConnectionStateChangedEvent>(
    const stream::StreamConnectionStateChangedEvent& val
) {
    return serializeBaseWithData<Event>(val, "stream$StreamConnectionStateChangedEvent");
}
