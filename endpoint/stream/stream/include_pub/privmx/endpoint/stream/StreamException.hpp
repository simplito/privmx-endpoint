/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_EXT_EXCEPTION_HPP_

#include "privmx/endpoint/core/Exception.hpp"

#define DECLARE_SCOPE_ENDPOINT_EXCEPTION(NAME, MSG, SCOPE, CODE, ...)                                                  \
    class NAME : public privmx::endpoint::core::Exception {                                                            \
    public:                                                                                                            \
        static constexpr unsigned int SCOPE_CODE = (CODE);                                                             \
        NAME() : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16)) {}                                 \
        NAME(const std::string& msg, const std::string& name, unsigned int code)                                       \
            : privmx::endpoint::core::Exception(msg, name, SCOPE, (CODE << 16) | code, std::string()) {}               \
        NAME(const std::string& msg, const std::string& name, unsigned int code, const std::string& description)       \
            : privmx::endpoint::core::Exception(msg, name, SCOPE, (CODE << 16) | code, description) {}                 \
        void rethrow() const override;                                                                                 \
    };                                                                                                                 \
    inline void NAME::rethrow() const {                                                                                \
        throw *this;                                                                                                   \
    };

#define DECLARE_ENDPOINT_EXCEPTION(BASE_SCOPED, NAME, MSG, CODE, ...)                                                  \
    class NAME : public BASE_SCOPED {                                                                                  \
    public:                                                                                                            \
        static constexpr unsigned int FULL_CODE = (BASE_SCOPED::SCOPE_CODE << 16) | (CODE);                            \
        NAME() : BASE_SCOPED(MSG, #NAME, CODE) {}                                                                      \
        NAME(const std::string& new_of_description) : BASE_SCOPED(MSG, #NAME, CODE, new_of_description) {}             \
        void rethrow() const override;                                                                                 \
    };                                                                                                                 \
    inline void NAME::rethrow() const {                                                                                \
        throw *this;                                                                                                   \
    };

namespace privmx {
namespace endpoint {
namespace stream {
// clang-format off
#define ENDPOINT_STREAM_EXCEPTION_CODE 0x00080000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointStreamException, "Unknown endpoint stream exception", "StreamRoom", 0x0008)

#define STREAM_EXCEPTIONS(X)                                                                                          \
    X(UnknowStreamRoomFormatException, "Unknown stream room format", 0x0005)                                          \
    X(WebRTCException, "WebRTC error", 0x0009)                                                                        \
    X(IncorrectStreamHandleException, "Incorrect stream handle", 0x000A)                                              \
    X(IncorrectTrackIdException, "Incorrect track id", 0x000C)                                                        \
    X(CannotExtractStreamRoomCreatedEventException, "Cannot extract StreamRoomCreatedEvent", 0x000F)                  \
    X(CannotExtractStreamRoomUpdatedEventException, "Cannot extract StreamRoomUpdatedEvent", 0x0010)                  \
    X(CannotExtractStreamRoomDeletedEventException, "Cannot extract StreamRoomDeletedEvent", 0x0011)                  \
    X(CannotExtractStreamPublishedEventException, "Cannot extract StreamPublishedEvent", 0x0012)                      \
    X(CannotExtractStreamRoomJoinedEventException, "Cannot extract StreamRoomJoinedEvent", 0x0013)                    \
    X(CannotExtractStreamUnpublishedEventException, "Cannot extract StreamUnpublishedEvent", 0x0014)                  \
    X(CannotExtractStreamRoomLeftEventException, "Cannot extract StreamRoomLeftEvent", 0x0015)                        \
    X(StreamRoomDataIntegrityException, "Failed StreamRoom data integrity check", 0x0018)                             \
    X(CannotExtractStreamSubscribedEventException, "Cannot extract StreamSubscribedEvent", 0x001B)                    \
    X(CannotExtractStreamUnsubscribedEventException, "Cannot extract StreamUnsubscribedEvent", 0x001C)                \
    X(InvalidTurnServerURIException, "Invalid turn server URI", 0x001D)                                               \
    X(StreamRoomConnectionNotInitialized, "StreamRoom connection not initialized", 0x0020)                            \
    X(StreamHandleNotInitialized, "StreamHandle not initialized", 0x0021)                                             \
    X(StreamAlreadyPublishedException, "Stream is already published", 0x0022)                                         \
    X(CannotExtractStreamUpdatedEventException, "Cannot extract StreamUpdatedEvent", 0x0023)                          \
    X(NullCallbackException, "Callback must not be null", 0x0024)                                                     \
    X(UnknownTypeException, "Unknown type encountered", 0x0025)                                                       \
    X(ThereCanBeOnlyOneDataTrackException, "There can be only one dataTrack per user in StreamRoom", 0x0026)          \
    X(DataTrackNotInitializedException, "Data track not initialized", 0x0027)                                         \
    X(NoStreamEncryptionKeyException, "No stream encryption key", 0x0028)                                             \
    X(NoStreamDecryptionKeyException, "No stream decryption key", 0x0029)                                             \
    X(InvalidEncryptionKeyIdLengthException, "Invalid encryption key id length", 0x002A)                              \
    X(InvalidMessageHeaderLengthException, "Invalid message header length", 0x002B)                                   \
    X(UnsupportedMessageFormatVersionException, "Unsupported message format version length", 0x002C)                  \
    X(AlreadyJoinedStreamRoomException, "StreamRoom already joined", 0x002D)                                          \
    X(InvalidDataChannelSeqException, "Invalid data channel sequence number", 0x002E)                                 \
    X(StreamHandleNotPublishedException, "StreamHandle not published", 0x002F)                                        \
    X(SubscriberStreamAlreadyCreatedException, "Subscriber stream is already created", 0x0030)                        \
    X(SubscriberStreamHandleNotInitialized, "SubscriberStreamHandle not initialized", 0x0031)

#define PRIVMX_STREAM_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointStreamException, NAME, MSG, CODE)
STREAM_EXCEPTIONS(PRIVMX_STREAM_DECLARE)
#undef PRIVMX_STREAM_DECLARE

// compile-time guard: codes are collected from the list above, never retyped
#define PRIVMX_STREAM_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(
    privmx::endpoint::core::exceptionCodesUnique({STREAM_EXCEPTIONS(PRIVMX_STREAM_CODE)}),
    "Duplicate exception code in stream scope"
);
#undef PRIVMX_STREAM_CODE
#undef STREAM_EXCEPTIONS
// clang-format on
} // namespace stream
} // namespace endpoint
} // namespace privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_STREAM_EXT_EXCEPTION_HPP_
