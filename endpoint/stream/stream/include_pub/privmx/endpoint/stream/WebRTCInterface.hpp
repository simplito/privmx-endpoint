/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_WEBRTCINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_WEBRTCINTERFACE_HPP_

#include <string>
#include <vector>

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/stream/Types.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

/**
 * Types of keys used to encrypt and decrypt Stream data.
 */
enum KeyType {
    /**
     * key used to encrypt the data sent by the local user
     */
    LOCAL,

    /**
     * key used to decrypt the data received from other participants
     */
    REMOTE
};

/**
 * Holds an encryption key of a Stream Room.
 */
struct Key {
    /**
     * ID of the key
     */
    std::string keyId;

    /**
     * key bytes
     */
    core::Buffer key;

    /**
     * determines whether the key is used to encrypt or to decrypt data
     */
    KeyType type;
};

/**
 * Interface of the WebRTC layer used by 'StreamApiLow'.
 * An implementation has to be provided when joining a Stream Room and is responsible for managing the PeerConnections
 * of that Stream Room - one for publishing ("publisher") and one for receiving ("subscriber") Streams.
 */
class WebRTCInterface {
public:
    /**
     * Creates an SDP offer for the given PeerConnection and sets it as its local description.
     *
     * @param streamRoomId ID of the Stream Room the connection belongs to
     * @param connectionType type of the connection ("publisher" or "subscriber")
     *
     * @return created offer SDP
     */
    virtual std::string createOfferAndSetLocalDescription(
        const std::string& streamRoomId,
        const std::string& connectionType
    ) = 0;

    /**
     * Sets the given session description as the remote description of the PeerConnection, creates an answer to it
     * and sets that answer as the PeerConnection's local description.
     *
     * @param streamRoomId ID of the Stream Room the connection belongs to
     * @param sdp received session description in the SDP format
     * @param type type of the received session description ("offer" or "answer")
     * @param connectionType type of the connection ("publisher" or "subscriber")
     *
     * @return created answer SDP
     */
    virtual std::string createAnswerAndSetDescriptions(
        const std::string& streamRoomId,
        const std::string& sdp,
        const std::string& type,
        const std::string& connectionType
    ) = 0;

    /**
     * Sets the received answer as the remote description of the PeerConnection.
     *
     * @param streamRoomId ID of the Stream Room the connection belongs to
     * @param sdp received session description in the SDP format
     * @param type type of the received session description ("offer" or "answer")
     * @param connectionType type of the connection ("publisher" or "subscriber")
     */
    virtual void setAnswerAndSetRemoteDescription(
        const std::string& streamRoomId,
        const std::string& sdp,
        const std::string& type,
        const std::string& connectionType
    ) = 0;

    /**
     * Assigns the media server session to the PeerConnection.
     * The session ID is needed to send the PeerConnection's ICE candidates (using trickle) to the server.
     *
     * @param streamRoomId ID of the Stream Room the connection belongs to
     * @param sessionId ID of the media server session assigned to the connection
     * @param connectionType type of the connection ("publisher" or "subscriber")
     */
    virtual void updateSessionId(
        const std::string& streamRoomId,
        const int64_t sessionId,
        const std::string& connectionType
    ) = 0;

    /**
     * Closes all PeerConnections of the given Stream Room.
     *
     * @param streamRoomId ID of the Stream Room to close the connections of
     */
    virtual void closeAll(const std::string& streamRoomId) = 0;

    /**
     * Closes a single PeerConnection of the given Stream Room.
     *
     * @param streamRoomId ID of the Stream Room the connection belongs to
     * @param connectionType type of the connection to close ("publisher" or "subscriber")
     */
    virtual void close(const std::string& streamRoomId, const std::string& connectionType) = 0;

    /**
     * Replaces the keys used to encrypt and decrypt the data sent over the publisher and subscriber Streams.
     *
     * @param streamRoomId ID of the Stream Room to update the keys of
     * @param keys new set of encryption keys
     */
    virtual void updateKeys(const std::string& streamRoomId, const std::vector<Key>& keys) = 0;

protected:
    /**
     * //doc-gen:ignore
     */
    virtual ~WebRTCInterface() = default;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_WEBRTCINTERFACE_HPP_
