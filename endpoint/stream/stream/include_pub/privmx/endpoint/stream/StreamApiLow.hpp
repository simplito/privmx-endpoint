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

#include "privmx/endpoint/stream/Types.hpp"
#include "privmx/endpoint/stream/WebRTCInterface.hpp"
#include <memory>
#include <optional>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ExtendedPointer.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <string>
#include <vector>

namespace privmx {
namespace endpoint {
namespace stream {

class StreamApiLowImpl;

/**
 * Represents Endpoint's API for Stream Rooms and Streams.
 *
 * It does not provide a WebRTC stack on its own - an implementation of 'WebRTCInterface' has to be passed when
 * joining a Stream Room. This API and that implementation drive each other: this API tells the WebRTC layer to
 * create and apply the session descriptions.
 *
 * Streaming in a Stream Room follows a fixed order: joinStreamRoom, then createStream and publishStream to send
 * media and/or createSubscriberStream to receive it, and finally leaveStreamRoom. Managing the Stream Rooms
 * themselves (creating, updating, listing, deleting) does not require joining them.
 */
class StreamApiLow : public privmx::endpoint::core::ExtendedPointer<StreamApiLowImpl> {
public:
    /**
     * Creates an instance of 'StreamApiLow'.
     *
     * @param connection instance of 'Connection'
     *
     * @return StreamApiLow object
     */
    static StreamApiLow create(const core::Connection& connection);

    /**
     * //doc-gen:ignore
     */
    StreamApiLow();
    StreamApiLow(const StreamApiLow& obj);
    StreamApiLow& operator=(const StreamApiLow& obj);
    StreamApiLow(StreamApiLow&& obj);
    ~StreamApiLow();

    /**
     * Gets credentials of the TURN servers.
     *
     * A TURN server relays the Streams when the network configuration blocks direct traffic, e.g. because of
     * a firewall or a double NAT.
     * The credentials expire, so they should be fetched again when a new connection is being configured rather
     * than stored for the lifetime of the application.
     *
     * @return list of TURN servers credentials
     */
    std::vector<TurnCredentials> getTurnCredentials();

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
     * 0 closes it immediately; std::nullopt use the server default (closes it immediately)
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
    // Stream

    /**
     * Gets a list of currently published Streams in given Stream Room.
     *
     * The returned Streams and their feeds are what can be passed to createSubscriberStream.
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
     * A user becomes a participant from the moment they call joinStreamRoom until they call leaveStreamRoom, and
     * may have no subscriptions and no published Stream in the meantime.
     *
     * @param streamRoomId ID of the Stream Room
     *
     * @return list of StreamSubscriber structs describing current participants
     */
    std::vector<StreamSubscriber> listStreamRoomParticipants(const std::string& streamRoomId);

    /**
     * Subscribe for the Stream Room events on the given subscription query.
     *
     * The queries are built by buildSubscriptionQuery. The returned IDs are the only way to stop receiving those
     * events, so they have to be kept for the matching unsubscribeFrom call.
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
     * The selector narrows the query down to a single scope, so 'selectorId' has to be an ID of the kind named by
     * 'selectorType' - a Context ID, a Stream Room ID or a Stream ID.
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
     * Sends a locally gathered ICE candidate to the media server.
     *
     * This is meant to be called by the WebRTC layer for every candidate it gathers, with the session ID which
     * this API has assigned to that Stream by calling 'WebRTCInterface::updateSessionId'.
     *
     * @param sessionId ID of the media server session the candidate belongs to
     * @param candidateAsJson ICE candidate in serialized JSON
     */
    void trickle(const int64_t sessionId, const std::string& candidateAsJson);

    /**
     * Sends a new offer to the media server to reconfigure an existing Stream.
     *
     * This method can be used to start the renegotiation process when the WebRTC layer signals that renegotiation
     * is needed on the PeerConnection observer.
     *
     * @param sessionId ID of the media server session to reconfigure
     * @param sdp offer created by the WebRTC layer
     */
    void setNewOfferOnReconfigure(const int64_t sessionId, const SdpWithTypeModel& sdp);

    /**
     * Joins a Stream Room using the given WebRTC layer implementation.
     *
     * This is required to work with the Streams, the Stream events and the data channels inside a Stream Room.
     * Joining passes the Stream Room's current encryption keys to the given WebRTC layer and keeps them up to date
     * for as long as the Stream Room is joined, so the same instance has to stay alive until leaveStreamRoom.
     * A Stream Room can be joined only once at a time.
     *
     * @param streamRoomId ID of the Stream Room to join
     * @param webRtc implementation of 'WebRTCInterface' handling the Stream Room's connections
     */
    void joinStreamRoom(
        const std::string& streamRoomId,
        std::shared_ptr<WebRTCInterface> webRtc
    ); // required before createStream and createSubscription

    /**
     * Leaves a Stream Room and closes all opened Publisher/Subscriber Streams.
     *
     * The handles of the Stream Room's publisher and subscriber Streams are invalidated by this call and the
     * Stream Room has to be joined again to publish or receive anything in it.
     * It also closes all the connections between PrivMX Bridge and the Stream Room in the Janus Gateway, so the
     * user disappears from the list of participants.
     *
     * @param streamRoomId ID of the Stream Room to leave
     */
    void leaveStreamRoom(const std::string& streamRoomId);
    // Publisher stream part

    /**
     * Creates a publisher Stream in given Stream Room.
     *
     * The Stream is only created locally - nothing is sent to the server and the Stream becomes visible to other
     * participants after calling publishStream.
     * A Stream Room can hold one publisher Stream at a time - creating a second one throws
     * 'StreamAlreadyPublishedException' until the current one is removed by removeStream.
     *
     * @param streamRoomId ID of the Stream Room to create the Stream in
     *
     * @return handle to the created Stream
     */
    StreamHandle createStream(const std::string& streamRoomId);

    /**
     * Publishes the Stream with the feeds currently added to it by the WebRTC layer.
     *
     * The feeds have to be added to the WebRTC layer's Publisher Connection before this call, because the offer
     * sent to the server is created from that PeerConnection's current state.
     * A publisher Stream has to have at least one feed added to be published successfully.
     *
     * @param streamHandle handle returned by createStream
     *
     * @return result of the publish operation
     */
    StreamPublishResult publishStream(const StreamHandle& streamHandle);

    /**
     * Updates an already published Stream after its feeds have changed (added or removed).
     *
     * As in publishStream, the changes have to be applied to the WebRTC layer's publisher connection first.
     * The Stream has to be published before.
     *
     * @param streamHandle handle returned by createStream
     *
     * @return result of the update operation
     */
    StreamPublishResult updateStream(const StreamHandle& streamHandle);

    /**
     * Stops publishing and closes the Publisher Stream.
     *
     * The handle is closed after this call and cannot be used anymore, but a new Publisher Stream can be created
     * in the same Stream Room with createStream.
     *
     * @param streamHandle handle returned by createStream
     */
    void removeStream(const StreamHandle& streamHandle);
    // Subscriber stream part

    /**
     * Creates a Subscriber Stream receiving the selected streams or tracks published in given Stream Room.
     *
     * A Stream Room can hold one subscriber Stream at a time - another one can be created only after the current
     * one is removed by removeSubscriberStream.
     * The 'subscriptions' list has to contain at least one feed to create a subscriber Stream successfully.
     * If the media server answers with an offer, the negotiation is completed internally using the Stream Room's
     * WebRTC layer, so the caller does not have to handle it.
     * A 'StreamSubscription' without 'streamTrackId' subscribes to all the tracks available in that Stream.
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
     * The resulting set of subscriptions is the current one without 'subscriptionsToRemove' plus
     * 'subscriptionsToAdd'. As in createSubscriberStream, the negotiation which may follow is completed internally.
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
     * The handle is closed after this call and cannot be used anymore, but a new subscriber Stream can be created
     * in the same Stream Room with createSubscriberStream.
     *
     * @param subscriptionHandle handle returned by createSubscriberStream
     */
    void removeSubscriberStream(const SubscriberStreamHandle& subscriptionHandle);
    // Data Channel
    /**
     * Encrypts a message to be sent over the Stream Room's data channel.
     *
     * The Stream Room has to be joined, as the message is encrypted with its current key.
     * The message's 'seq' is assigned by the caller and has to grow strictly with every message sent over the same
     * Stream - the receiving side rejects a message whose 'seq' is not greater than the last accepted one.
     *
     * @param streamRoomId ID of the Stream Room to send the message in
     * @param plainMessage message to encrypt
     *
     * @return encrypted message
     */
    core::Buffer encryptDataChannelMessage(const std::string& streamRoomId, const DataChannelMessage& plainMessage);

    /**
     * Decrypts a message received over the Stream Room's data channel.
     *
     * A message which cannot be decrypted is reported by the 'statusCode' of the returned struct rather than by an
     * exception, so that a single broken message does not break the whole data channel. A message with an invalid
     * sequence number throws 'InvalidDataChannelSeqException', so the same message cannot be decrypted twice.
     *
     * @param streamRoomId ID of the Stream Room the message was received in
     * @param remoteStreamId ID of the remote Stream which sent the message
     * @param encryptedData received encrypted message
     *
     * @return decrypted message
     */
    DecryptedDataChannelMessage decryptDataChannelMessage(
        const std::string& streamRoomId,
        const std::string& remoteStreamId,
        const core::Buffer& encryptedData
    );

private:
    StreamApiLow(const std::shared_ptr<StreamApiLowImpl>& impl);
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPILOW_HPP_
