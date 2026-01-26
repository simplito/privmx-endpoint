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

#include <Poco/Dynamic/Var.h>

#include <functional>
#include <memory>
#include <optional>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ExtendedPointer.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <string>
#include <vector>

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/stream/Types.hpp"
#include "privmx/endpoint/stream/WebRTCInterface.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

class StreamApiLowImpl;

class StreamApiLow : public privmx::endpoint::core::ExtendedPointer<StreamApiLowImpl> {
public:

    static StreamApiLow create(const core::Connection& connection, event::EventApi& eventApi);
    StreamApiLow();
    StreamApiLow(const StreamApiLow& obj);
    StreamApiLow& operator=(const StreamApiLow& obj);
    StreamApiLow(StreamApiLow&& obj);
    ~StreamApiLow();

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
    std::vector<StreamInfo> listStreams(const std::string& streamRoomId);
    void joinStreamRoom(const std::string& streamRoomId, std::shared_ptr<WebRTCInterface> webRtc); // required before createStream and openStream
    void leaveStreamRoom(const std::string& streamRoomId);
    void enableStreamRoomRecording(const std::string& streamRoomId);
    std::vector<stream::RecordingEncKey> getStreamRoomRecordingKeys(const std::string& streamRoomId);
    StreamHandle createStream(const std::string& streamRoomId);
    StreamPublishResult publishStream(const StreamHandle& streamHandle);
    StreamPublishResult updateStream(const StreamHandle& streamHandle);
    void unpublishStream(const StreamHandle& streamHandle);

    void subscribeToRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptions, const Settings& options);
    void modifyRemoteStreamsSubscriptions(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToAdd, const std::vector<StreamSubscription>& subscriptionsToRemove, const Settings& options);
    void unsubscribeFromRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToRemove);

    void trickle(const int64_t sessionId, const std::string& candidateAsJson);
    void acceptOfferOnReconfigure(const int64_t sessionId, const SdpWithTypeModel& sdp);

    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);
    std::string buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId);

    void keyManagement(const std::string& streamRoomId, bool disable);
private:
    StreamApiLow(const std::shared_ptr<StreamApiLowImpl>& impl);
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPILOW_HPP_
