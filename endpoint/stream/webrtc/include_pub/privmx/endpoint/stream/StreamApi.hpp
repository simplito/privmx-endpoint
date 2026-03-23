/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_HPP_

#include <functional>
#include <memory>
#include <optional>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <string>
#include <vector>
#include "privmx/endpoint/stream/webrtc/Types.hpp"
#include "privmx/endpoint/stream/webrtc/OnTrackInterface.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

class StreamApiImpl;

/**
 * 'StreamApi' is a class representing Endpoint's API for Stream Rooms and WebRTC streams.
 */
class StreamApi {
public:

    /**
     * Creates an instance of 'StreamApi'.
     *
     * @param connection instance of 'Connection'
     * @param eventApi instance of 'EventApi'
     *
     * @return StreamApi object
     */
    static StreamApi create(core::Connection& connection, event::EventApi& eventApi);

    /**
     * //doc-gen:ignore
     */
    StreamApi() = default;

    /**
     * Creates a new Stream Room in given Context.
     *
     * @param contextId ID of the Context to create the Stream Room in
     * @param users vector of UserWithPubKey structs which indicates who will have access to the created Stream Room
     * @param managers vector of UserWithPubKey structs which indicates who will have access (and management rights) to
     * the created Stream Room
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param policies Stream Room's policies (pass std::nullopt to use defaults)
     *
     * @return created Stream Room ID
     */
    std::string createStreamRoom(
        const std::string& contextId, 
        const std::vector<core::UserWithPubKey>& users, 
        const std::vector<core::UserWithPubKey>&managers,
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies
    );

    /**
     * Updates an existing Stream Room.
     *
     * @param streamRoomId ID of the Stream Room to update
     * @param users vector of UserWithPubKey structs which indicates who will have access to the Stream Room
     * @param managers vector of UserWithPubKey structs which indicates who will have access (and management rights) to
     * the Stream Room
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param version current version of the updated Stream Room
     * @param force force update (without checking version)
     * @param forceGenerateNewKey force to regenerate a key for the Stream Room
     * @param policies Stream Room's policies (pass std::nullopt to keep current/defaults)
     */
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

    /**
     * Gets a list of Stream Rooms in given Context.
     *
     * @param contextId ID of the Context to get the Stream Rooms from
     * @param query struct with list query parameters
     *
     * @return struct containing list of Stream Rooms
     */
    core::PagingList<StreamRoom> listStreamRooms(const std::string& contextId, const core::PagingQuery& query);

    /**
     * Gets a single Stream Room by given Stream Room ID.
     *
     * @param streamRoomId ID of the Stream Room to get
     *
     * @return struct containing information about the Stream Room
     */
    StreamRoom getStreamRoom(const std::string& streamRoomId);

    /**
     * Deletes a Stream Room by given Stream Room ID.
     *
     * @param streamRoomId ID of the Stream Room to delete
     */
    void deleteStreamRoom(const std::string& streamRoomId);

    /**
     * Subscribe for the Stream Room events on the given subscription query.
     *
     * @param subscriptionQueries list of queries
     * @return list of subscriptionIds in maching order to subscriptionQueries
     */
    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);

    /**
     * Unsubscribe from events for the given subscriptionId.
     *
     * @param subscriptionIds list of subscriptionId
     */
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);

    /**
     * Generate subscription Query for the Stream Room events.
     *
     * @param eventType type of event which you listen for
     * @param selectorType scope on which you listen for events
     * @param selectorId ID of the selector
     *
     * @return subscription query string
     */
    std::string buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId);

    /**
     * Gets a list of currently published streams in given Stream Room.
     *
     * @param streamRoomId ID of the Stream Room to list streams from
     * @return list of StreamInfo structs describing currently published streams
     */
    std::vector<StreamInfo> listStreams(const std::string& streamRoomId);

    /**
     * Joins a Stream Room.
     * This is required before calling createStream/publishStream and subscribing to remote streams in the room.
     *
     * @param streamRoomId ID of the Stream Room to join
     */
    void joinStreamRoom(const std::string& streamRoomId); // required before createStream and openStream

    /**
     * Leaves a Stream Room.
     *
     * @param streamRoomId ID of the Stream Room to leave
     */
    void leaveStreamRoom(const std::string& streamRoomId);

    /**
     * Enables server-side recording for the Stream Room.
     *
     * @param streamRoomId ID of the Stream Room
     */
    void enableStreamRoomRecording(const std::string& streamRoomId);

    /**
     * Gets encryption keys used for Stream Room recordings.
     *
     * @param streamRoomId ID of the Stream Room
     * @return list of recording encryption keys
     */
    std::vector<stream::RecordingEncKey> getStreamRoomRecordingKeys(const std::string& streamRoomId);

    /**
     * Creates a local Stream handle for publishing media in given Stream Room.
     * Call addTrack/removeTrack to prepare tracks and publishStream/updateStream to send changes to the server.
     *
     * @param streamRoomId ID of the Stream Room to create the stream in
     * @return handle to a local Stream instance
     */
    StreamHandle createStream(const std::string& streamRoomId);

    /**
     * Lists available local audio input devices.
     *
     * @return list of audio devices
     */
    std::vector<AudioDevice> getAudioDevices();

    /**
     * Lists available local video input devices (cameras).
     *
     * @return list of video devices
     */
    std::vector<VideoDevice> getVideoDevices();

    /**
     * Lists available desktop capture sources.
     *
     * @param desktopType type of desktop source (screen/window)
     * @return list of desktop devices
     */
    std::vector<DesktopDevice> getDesktopDevices(DesktopType desktopType);

    /**
     * Adds a local media track to a Stream handle.
     * The track is staged locally and becomes visible to others after publishStream/updateStream.
     *
     * @param streamHandle handle returned by createStream
     * @param track media device to capture from
     * @param mediaTrackConstrains capture constraints (resolution/fps)
     * @return MediaTrack helper allowing to enable/disable the track
     */
    MediaTrack addTrack(const StreamHandle& streamHandle, const MediaDevice& track, const MediaTrackConstrains& mediaTrackConstrains);

    /**
     * Removes a previously added media track from a Stream handle.
     * For already published streams the removal is applied on updateStream.
     *
     * @param streamHandle handle returned by createStream
     * @param track media device previously passed to addTrack
     */
    void removeTrack(const StreamHandle& streamHandle, const MediaDevice& track);

    /**
     * Publishes the Stream (with currently staged tracks) to the server.
     *
     * @param streamHandle handle returned by createStream
     * @return result of the publish operation
     */
    StreamPublishResult publishStream(const StreamHandle& streamHandle);

    /**
     * Updates a published Stream after adding/removing tracks.
     *
     * @param streamHandle handle returned by createStream
     * @return result of the update operation
     */
    StreamPublishResult updateStream(const StreamHandle& streamHandle);

    /**
     * Stops publishing the Stream.
     *
     * @param streamHandle handle returned by createStream
     */
    void unpublishStream(const StreamHandle& streamHandle);

    /**
     * Subscribes to selected remote streams (and optionally specific tracks) in the Stream Room.
     *
     * @param streamRoomId ID of the Stream Room
     * @param subscriptions list of remote streams/tracks to subscribe to
     */
    void subscribeToRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptions);

    /**
     * Modifies current remote streams subscriptions.
     *
     * @param streamRoomId ID of the Stream Room
     * @param subscriptionsToAdd list of subscriptions to add
     * @param subscriptionsToRemove list of subscriptions to remove
     */
    void modifyRemoteStreamsSubscriptions(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToAdd, const std::vector<StreamSubscription>& subscriptionsToRemove);

    /**
     * Unsubscribes from selected remote streams (and optionally specific tracks) in the Stream Room.
     *
     * @param streamRoomId ID of the Stream Room
     * @param subscriptionsToRemove list of subscriptions to remove
     */
    void unsubscribeFromRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToRemove);

    /**
     * Configures whether to drop encrypted frames that cannot be decrypted.
     *
     * @param streamRoomId ID of the Stream Room
     * @param enable if true, broken frames will be dropped
     */
    void dropBrokenFrames(const std::string& streamRoomId, bool enable);

    /**
     * Registers a listener for remote tracks in the Stream Room.
     *
     * @param streamRoomId ID of the Stream Room
     * @param streamId optional remote stream ID to filter events (std::nullopt for all streams)
     * @param onTrack listener implementation
     */
    void addRemoteStreamListener(const std::string& streamRoomId, std::optional<int64_t> streamId, std::shared_ptr<OnTrackInterface> onTrack);

    /**
     * Send binary data by Track::Raw
     *
     * @param streamHandle handle returned by createStream
     * @param data data to send
     */
    void sendData(const StreamHandle& streamHandle, core::Buffer data);

    /**
     * //doc-gen:ignore
     */
    std::shared_ptr<StreamApiImpl> getImpl() const { return _impl; }

private:
    void validateEndpoint();
    StreamApi(const std::shared_ptr<StreamApiImpl>& impl);
    std::shared_ptr<StreamApiImpl> _impl;
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_HPP_
