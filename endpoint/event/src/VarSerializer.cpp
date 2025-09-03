/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/event/VarSerializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
Poco::Dynamic::Var VarSerializer::serialize<event::ContextCustomEvent>(const event::ContextCustomEvent& val) {
    return serializeBaseWithData<Event>(val, "event$ContextCustomEvent");
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<event::ContextCustomEventData>(const event::ContextCustomEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "event$ContextCustomEventData");
    }
    obj->set("contextId", serialize(val.contextId));
    obj->set("userId", serialize(val.userId));
    obj->set("payload", serialize(val.payload));
    obj->set("statusCode", serialize(val.statusCode));
    obj->set("schemaVersion", serialize(val.schemaVersion));

    return obj;
}

