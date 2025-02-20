/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/core/EventVarSerializer.hpp>

#include "privmx/endpoint/event/Events.hpp"
#include "privmx/endpoint/event/EventException.hpp"
#include "privmx/endpoint/event/EventVarSerializer.hpp"
using namespace privmx::endpoint;
using namespace privmx::endpoint::event;

std::string ContextCustomEvent::toJSON() const {
    return core::JsonSerializer<ContextCustomEvent>::serialize(*this);
}

std::shared_ptr<core::SerializedEvent> ContextCustomEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

bool Events::isContextCustomEvent(const core::EventHolder& handler) {
    return handler.type() == "contextCustom";
}

ContextCustomEvent Events::extractContextCustomEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<ContextCustomEvent>(handler.get());
        if (!event) {
            throw CannotExtractContextCustomEvent();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}


