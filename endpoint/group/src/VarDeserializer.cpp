/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/VarDeserializer.hpp"

#include <privmx/endpoint/core/CoreException.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
group::EventType VarDeserializer::deserialize<group::EventType>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    switch (val.convert<int64_t>()) {
        case group::EventType::GROUP_CREATE:
            return group::EventType::GROUP_CREATE;
        case group::EventType::GROUP_UPDATE:
            return group::EventType::GROUP_UPDATE;
        case group::EventType::GROUP_DELETE:
            return group::EventType::GROUP_DELETE;
    }
    // Rejected rather than defaulted: a value the binding does not know means the caller and this build disagree
    // about the enum, and guessing would subscribe them to the wrong events.
    throw InvalidParamsException(
        name + " | " + ("Unknown group::EventType value, received " + std::to_string(val.convert<int64_t>()))
    );
}

template<>
group::EventSelectorType VarDeserializer::deserialize<group::EventSelectorType>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    switch (val.convert<int64_t>()) {
        case group::EventSelectorType::CONTEXT_ID:
            return group::EventSelectorType::CONTEXT_ID;
        case group::EventSelectorType::GROUP_ID:
            return group::EventSelectorType::GROUP_ID;
    }
    throw InvalidParamsException(
        name + " | " + ("Unknown group::EventSelectorType value, received " + std::to_string(val.convert<int64_t>()))
    );
}
