/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/EventVarSerializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>

#include "privmx/endpoint/stream/StreamException.hpp"
#include "privmx/endpoint/stream/StreamWebRTCVarSerializer.hpp"
#include "privmx/endpoint/stream/webrtc/Events.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

std::string StreamConnectionStateChangedEvent::toJSON() const {
    return core::JsonSerializer<StreamConnectionStateChangedEvent>::serialize(*this);
}

std::shared_ptr<core::SerializedEvent> StreamConnectionStateChangedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(
        core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)}
    );
}

bool StreamConnectionEvents::isStreamConnectionStateChangedEvent(const core::EventHolder& handler) {
    return handler.type() == "streamConnectionStateChanged";
}

StreamConnectionStateChangedEvent StreamConnectionEvents::extractStreamConnectionStateChangedEvent(
    const core::EventHolder& handler
) {
    try {
        auto event = std::dynamic_pointer_cast<StreamConnectionStateChangedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStreamConnectionStateChangedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
