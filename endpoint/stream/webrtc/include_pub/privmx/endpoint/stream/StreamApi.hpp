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

#include "privmx/endpoint/stream/webrtc/OnTrackInterface.hpp"
#include "privmx/endpoint/stream/webrtc/Types.hpp"
#include <memory>
#include <optional>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <string>
#include <vector>

namespace privmx {
namespace endpoint {
namespace stream {

class StreamApiImpl;

/**
 * Represents Endpoint's API for Stream Rooms and Streams, with a built-in WebRTC layer.
 *
 * `StreamApi` handles everything `StreamApiLow` leaves to you: it configures the TURN servers, negotiates the
 * PeerConnections, captures the local media devices, and encrypts the media it sends. Use `StreamApiLow` instead
 * when you bring your own WebRTC stack.
 *
 * Streaming in a Stream Room follows a fixed order: `joinStreamRoom`, then `createStream`, `addTrack`, and
 * `publishStream` to send media and `createSubscriberStream` to receive it, and finally `leaveStreamRoom`.
 * Managing the Stream Rooms themselves, that is creating, updating, listing, and deleting them, works without
 * joining them.
 */
class StreamApi {
public:
    /**
     * Creates an instance of `StreamApi`.
     *
     * This method reads the TURN credentials from PrivMX Bridge and initializes the WebRTC stack with them, so the
     * given `Connection` has to be connected.
     *
     * @param connection instance of `Connection`
     * @param eventApi (deprecated) instance of `EventApi`, the value is ignored
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
     * @param emptyRoomTtl grace period (ms) the Stream Room stays open after the last participant leaves;
     * 0 closes it immediately; std::nullopt uses the server default (closes it immediately)
     *
     * @return ID of the created Stream Room
     */
    std::string createStreamRoom(
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicyWithoutItem>& policies,
        const std::optional<int64_t>& emptyRoomTtl = std::nullopt
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
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const int64_t version,
        const bool force,
        const bool forceGenerateNewKey,
        const std::optional<core::ContainerPolicyWithoutItem>& policies
    );

    /**
     * Gets a list of Stream Rooms in given Context.
     *
     * @param contextId ID of the Context to get the Stream Rooms from
     * @param query struct with list query parameters
     *
     * @return struct containing a list of Stream Rooms
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
     * Build the queries with `buildSubscriptionQuery`. The returned IDs are the only way to stop receiving those
     * events, so keep them for the matching `unsubscribeFrom` call.
     *
     * @param subscriptionQueries list of queries
     * @return list of subscriptionIds in matching order to subscriptionQueries
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
     * The selector narrows the query down to a single scope, so `selectorId` has to be an ID of the kind named by
     * `selectorType`: a Context ID, a Stream Room ID, or a Stream ID.
     *
     * @param eventType type of event which you listen for
     * @param selectorType scope on which you listen for events
     * @param selectorId ID of the selector
     *
     * @return subscription query string
     */
    std::string buildSubscriptionQuery(
        EventType eventType,
        EventSelectorType selectorType,
        const std::string& selectorId
    );

    /**
     * Gets a list of currently published Streams in given Stream Room.
     *
     * The returned Streams and their tracks are what you pass to `createSubscriberStream`.
     *
     * @param streamRoomId ID of the Stream Room to list the Streams from
     *
     * @return list of StreamInfo structs describing currently published Streams
     */
    std::vector<StreamInfo> listStreams(const std::string& streamRoomId);

    /**
     * Gets a list of participants of given Stream Room.
     *
     * Each participant is described by their current subscriptions and by the Stream they publish, if any.
     * A user becomes a participant from the moment they call `joinStreamRoom` until they call `leaveStreamRoom`,
     * and may have no subscriptions and no published Stream in the meantime.
     *
     * @param streamRoomId ID of the Stream Room
     *
     * @return list of StreamSubscriber structs describing current participants
     */
    std::vector<StreamSubscriber> listStreamRoomParticipants(const std::string& streamRoomId);

    /**
     * Joins a Stream Room.
     *
     * This is required to work with the Streams, the Stream events, and the data tracks inside a Stream Room.
     * Joining hands the Stream Room's encryption keys to the built-in WebRTC layer and keeps them up to date for as
     * long as the Stream Room is joined.
     * A Stream Room accepts one join at a time.
     *
     * @param streamRoomId ID of the Stream Room to join
     */
    void joinStreamRoom(const std::string& streamRoomId); // required before createStream and openStream

    /**
     * Leaves a Stream Room and closes all its Publisher and Subscriber Streams.
     *
     * This call invalidates the handles of the Stream Room's Streams and closes their PeerConnections, so the user
     * disappears from the list of participants. Join the Stream Room again to publish or receive anything in it.
     *
     * @param streamRoomId ID of the Stream Room to leave
     */
    void leaveStreamRoom(const std::string& streamRoomId);

    /**
     * Creates a Publisher Stream in given Stream Room.
     *
     * The Stream lives locally until you publish it: add its tracks with `addTrack` and then call `publishStream`
     * to make the Stream visible to the other participants.
     * A Stream Room holds one Publisher Stream at a time. Remove the current one with `removeStream` before you
     * create another.
     *
     * @param streamRoomId ID of the Stream Room to create the Stream in
     *
     * @return handle to the created Stream
     */
    StreamHandle createStream(const std::string& streamRoomId);

    /**
     * Lists the local audio input devices.
     *
     * Pass one of the returned devices to `addTrack` to capture from it.
     *
     * @return list of audio devices
     */
    std::vector<AudioDevice> getAudioDevices();

    /**
     * Lists the local video input devices, that is the cameras.
     *
     * Pass one of the returned devices to `addTrack` to capture from it.
     *
     * @return list of video devices
     */
    std::vector<VideoDevice> getVideoDevices();

    /**
     * Lists the local desktop capture sources.
     *
     * Pass one of the returned devices to `addTrack` to capture from it.
     *
     * @param desktopType type of the desktop source: `Screen` or `Window`
     *
     * @return list of desktop devices
     */
    std::vector<DesktopDevice> getDesktopDevices(DesktopType desktopType);

    /**
     * Adds a track to a Publisher Stream.
     *
     * The track stays local until the next `publishStream` or `updateStream` call, which sends it to the other
     * participants. A device unknown to the system throws `IncorrectTrackIdException`.
     * A Stream carries at most one data track, that is one device of the `Plain` type. Adding a second one throws
     * `ThereCanBeOnlyOneDataTrackException`.
     *
     * @param streamHandle handle returned by createStream
     * @param track media device to capture from
     * @param mediaTrackConstrains capture constraints, which apply to the video and desktop devices only
     *
     * @return MediaTrack struct which enables and disables the track
     */
    MediaTrack addTrack(
        const StreamHandle& streamHandle,
        const MediaDevice& track,
        const MediaTrackConstrains& mediaTrackConstrains
    );

    /**
     * Removes a track from a Publisher Stream.
     *
     * A track which has never been published disappears right away. A published one stays with the other
     * participants until the next `updateStream` call.
     *
     * @param streamHandle handle returned by createStream
     * @param track media device previously passed to addTrack
     */
    void removeTrack(const StreamHandle& streamHandle, const MediaDevice& track);

    /**
     * Publishes the Stream with the tracks currently added to it.
     *
     * This method starts the capturers of the added tracks and sends them to the media server. A Stream which is
     * already published throws `StreamAlreadyPublishedException`.
     * A publisher Stream has to have at least one feed added to be published successfully.
     *
     * @param streamHandle handle returned by createStream
     *
     * @return result of the publish operation
     */
    StreamPublishResult publishStream(const StreamHandle& streamHandle);

    /**
     * Updates an already published Stream after its tracks have changed.
     *
     * This method applies every `addTrack` and `removeTrack` call made since the Stream was published.
     *
     * @param streamHandle handle returned by createStream
     *
     * @return result of the update operation
     */
    StreamPublishResult updateStream(const StreamHandle& streamHandle);

    /**
     * Stops publishing the Stream and closes it.
     *
     * @param streamHandle handle returned by createStream
     */
    void removeStream(const StreamHandle& streamHandle);

    /**
     * Creates a Subscriber Stream receiving the selected Streams or tracks published in given Stream Room.
     *
     * A Stream Room holds one Subscriber Stream at a time. Remove the current one with `removeSubscriberStream`
     * before you create another.
     * The 'subscriptions' list has to contain at least one feed to create a subscriber Stream successfully.
     * A `StreamSubscription` without `streamTrackId` subscribes to all the tracks available in that Stream.
     * Register a listener with `addRemoteStreamListener` to receive the media of the subscribed Streams.
     *
     * @param streamRoomId ID of the Stream Room to create the Stream in
     * @param subscriptions list of Streams and tracks to subscribe to
     *
     * @return handle to the created Stream
     */
    SubscriberStreamHandle createSubscriberStream(
        const std::string& streamRoomId,
        const std::vector<StreamSubscription>& subscriptions
    );

    /**
     * Modifies the subscriptions of an existing Subscriber Stream.
     *
     * The resulting set of subscriptions is the current one without `subscriptionsToRemove` plus
     * `subscriptionsToAdd`.
     *
     * @param subscriptionHandle handle returned by createSubscriberStream
     * @param subscriptionsToAdd list of subscriptions to add
     * @param subscriptionsToRemove list of subscriptions to remove
     */
    void updateSubscriberStream(
        const SubscriberStreamHandle& subscriptionHandle,
        const std::vector<StreamSubscription>& subscriptionsToAdd,
        const std::vector<StreamSubscription>& subscriptionsToRemove
    );

    /**
     * Unsubscribes from all the Streams received by the given Subscriber Stream and closes it.
     *
     * @param subscriptionHandle handle returned by createSubscriberStream
     */
    void removeSubscriberStream(const SubscriberStreamHandle& subscriptionHandle);

    /**
     * Configures what the Stream Room does with the frames it fails to decrypt.
     *
     * By default such frames reach the receiving track as they are. Enable this option to drop them instead.
     *
     * @param streamRoomId ID of the Stream Room
     * @param enable true drops the frames which fail to decrypt
     */
    void dropBrokenFrames(const std::string& streamRoomId, bool enable);

    /**
     * Registers a listener for the remote tracks in the Stream Room.
     *
     * The listener receives the tracks which the Subscriber Stream subscribes to.
     *
     * @param streamRoomId ID of the Stream Room
     * @param streamId ID of a single remote Stream to listen to, or std::nullopt to listen to all of them
     * @param onTrack listener implementation
     */
    void addRemoteStreamListener(
        const std::string& streamRoomId,
        std::optional<int64_t> streamId,
        std::shared_ptr<OnTrackInterface> onTrack
    );

    /**
     * Encrypts and sends binary data over the Stream's data track.
     *
     * The Stream needs a published data track, that is a device of the `Plain` type added with `addTrack` and sent
     * by `publishStream` or `updateStream`. Otherwise this method throws `DataTrackNotInitializedException`.
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

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_HPP_
