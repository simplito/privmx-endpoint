/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPILOW_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPILOW_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <functional>
#include <Poco/Dynamic/Var.h>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include "privmx/endpoint/stream/Types.hpp"
#include "privmx/endpoint/stream/WebRTCInterface.hpp"


namespace privmx {
namespace endpoint {
namespace stream {

class StreamApiLowImpl;

class StreamApiLow {
public:

    static StreamApiLow create(const core::Connection& connection, event::EventApi& eventApi);
    StreamApiLow() = default;

    std::vector<TurnCredentials> getTurnCredentials();

    std::string createStreamRoom(
        const std::string& contextId, 
        const std::vector<core::UserWithPubKey>& users, 
        const std::vector<core::UserWithPubKey>&managers,
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies
    );

    void updateStreamRoom(
        const std::string& streamRoomId, 
        const std::vector<core::UserWithPubKey>& users, 
        const std::vector<core::UserWithPubKey>&managers,
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta, 
        const int64_t version, 
        const bool force, 
        const bool forceGenerateNewKey, 
        const std::optional<core::ContainerPolicy>& policies
    );

    core::PagingList<StreamRoom> listStreamRooms(const std::string& contextId, const core::PagingQuery& query);

    StreamRoom getStreamRoom(const std::string& streamRoomId);

    void deleteStreamRoom(const std::string& streamRoomId);
    // Stream
    int64_t createStream(const std::string& streamRoomId, int64_t localStreamId, std::shared_ptr<WebRTCInterface> webRtc);
    
    void publishStream(int64_t localStreamId);

    int64_t joinStream(const std::string& streamRoomId, const std::vector<int64_t>& streamsId, const Settings& settings, int64_t localStreamId, std::shared_ptr<WebRTCInterface> webRtc);

    std::vector<Stream> listStreams(const std::string& streamRoomId);

    void unpublishStream(int64_t localStreamId);

    void leaveStream(int64_t localStreamId);

    void trickle(const int64_t sessionId, const std::string& candidateAsJson);

    void subscribeForStreamEvents();
    void unsubscribeFromStreamEvents();

    void keyManagement(bool disable);
    void reconfigureStream(int64_t localStreamId, const std::string& optionsJSON = "{}");
    std::shared_ptr<StreamApiLowImpl> getImpl() const { return _impl; }

private:
    void validateEndpoint();

    StreamApiLow(const std::shared_ptr<StreamApiLowImpl>& impl);
    std::shared_ptr<StreamApiLowImpl> _impl;
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPILOW_HPP_
