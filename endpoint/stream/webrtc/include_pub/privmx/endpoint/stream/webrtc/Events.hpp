/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_WEBRTC_EVENTS_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_WEBRTC_EVENTS_HPP_

#include <privmx/endpoint/core/Events.hpp>
#include <privmx/endpoint/stream/webrtc/Types.hpp>

namespace privmx {
namespace endpoint {
namespace stream {

/**
 * Holds data of event that arrives when the media connections of a joined Stream Room change their state.
 *
 * Subscribe for it with 'StreamApi::buildConnectionStateSubscriptionQuery'. Unlike the Stream events of
 * 'StreamApiLow' it is raised by 'StreamApi' itself rather than by the Bridge, and it covers a Stream Room
 * you only watch just as well as one you publish to.
 */
struct StreamConnectionStateChangedEvent : public core::Event {

    /**
     * Event constructor
     */
    StreamConnectionStateChangedEvent() : core::Event("streamConnectionStateChanged") {}

    /**
     * Get Event as JSON string
     *
     * @return JSON string
     */
    std::string toJSON() const override;

    /**
     * //doc-gen:ignore
     */
    std::shared_ptr<core::SerializedEvent> serialize() const override;

    /**
     * new state of the Stream Room's media connections
     */
    StreamConnectionStateChangedEventData data;
};

/**
 * 'StreamConnectionEvents' provides the helper methods for the events which 'StreamApi' raises itself.
 */
class StreamConnectionEvents {
public:
    /**
     * Checks whether event held in the 'EventHolder' is a 'StreamConnectionStateChangedEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'StreamConnectionStateChangedEvent', else otherwise
     */
    static bool isStreamConnectionStateChangedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as a 'StreamConnectionStateChangedEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'StreamConnectionStateChangedEvent' object
     */
    static StreamConnectionStateChangedEvent extractStreamConnectionStateChangedEvent(
        const core::EventHolder& eventHolder
    );
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_WEBRTC_EVENTS_HPP_
