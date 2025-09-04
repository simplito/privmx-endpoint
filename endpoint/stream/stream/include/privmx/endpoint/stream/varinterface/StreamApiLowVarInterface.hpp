/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPILOWVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPILOWVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/stream/StreamApiLow.hpp"
#include "privmx/endpoint/stream/StreamVarSerializer.hpp"
#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <privmx/endpoint/stream/StreamVarDeserializer.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <mutex>
#include <shared_mutex>
namespace privmx {
namespace endpoint {
namespace stream {

class StreamApiLowVarInterface {
public:
    enum METHOD {
        Create = 0,
        GetTurnCredentials = 1,
        CreateStreamRoom = 2,
        UpdateStreamRoom = 3,
        ListStreamRooms = 4,
        GetStreamRoom = 5,
        DeleteStreamRoom = 6,
        CreateStream = 7,
        PublishStream = 8,
        JoinStream = 9,
        ListStreams = 10,
        UnpublishStream = 11,
        LeaveStream = 12,
        KeyManagement = 13,
        SubscribeForStreamEvents = 14,
        UnsubscribeFromStreamEvents = 15
    };

    StreamApiLowVarInterface(core::Connection connection, event::EventApi eventApi, const core::VarSerializer& serializer)
        : _connection(std::move(connection)), _eventApi(std::move(eventApi)), _serializer(serializer) {}

    Poco::Dynamic::Var create(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getTurnCredentials(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createStreamRoom(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateStreamRoom(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listStreamRooms(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getStreamRoom(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var deleteStreamRoom(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createStream(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var publishStream(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var joinStream(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listStreams(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unpublishStream(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var leaveStream(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var keyManagement(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeForStreamEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFromStreamEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

    std::shared_ptr<WebRTCInterface> getWebRtcInterface();
    void setWebRtcInterface(std::shared_ptr<WebRTCInterface> webRtcInterface);
    int64_t getWebRtcInterfaceRawPtr();
private:
    static std::map<METHOD, Poco::Dynamic::Var (StreamApiLowVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::Connection _connection;
    event::EventApi _eventApi;
    StreamApiLow _streamApi;
    core::VarSerializer _serializer;
    core::VarDeserializer _deserializer;
    std::shared_ptr<WebRTCInterface> _webRtcInterface;
    std::shared_mutex _mutex;
};

}  // namespace event
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPILOWVARINTERFACE_HPP_
