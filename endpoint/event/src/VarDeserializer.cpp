/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/event/VarDeserializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include <privmx/endpoint/core/CoreException.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
event::EventSelectorType VarDeserializer::deserialize<event::EventSelectorType>(const Poco::Dynamic::Var& val, const std::string& name) {

    switch (val.convert<int64_t>()) {
        case event::EventSelectorType::CONTEXT_ID:
            return event::EventSelectorType::CONTEXT_ID;
    }
    throw InvalidParamsException(name + " | " + ("Unknown event::EventSelectorType value, received " + std::to_string(val.convert<int64_t>())));
}

