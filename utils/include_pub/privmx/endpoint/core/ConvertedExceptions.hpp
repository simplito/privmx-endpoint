#ifndef _PRIVMXLIB_ENDPOINT_CONVERTED_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_CONVERTED_EXT_EXCEPTION_HPP_

/**
 * The Bridge's errors as C++ exceptions, one class per row of its own `src/api/AppException.ts`. The
 * exceptions each library layer raises itself are declared by that layer instead, in its own
 * PrivmxExtExceptions / CryptoException / RpcException / PrivFsException header.
 *
 * Two lists, split the way the Bridge reports a code: the high half picks the family, the low half the error
 * within it. `PRIVMX_SERVER_REQUEST_ERRORS` holds the JSON-RPC errors, whose negative codes reach us as family
 * 0xFFFF (-32602 arrives as 0xFFFF80A6, so the row carries 0x80A6). `PRIVMX_SERVER_ERRORS` holds the
 * application errors, family 0x0000, whose codes are written in the Bridge's table as they travel.
 *
 * Each row is (class name, message, code). A class name mirrors the Bridge's constant in PascalCase, except
 * where one was already published under another name - those are kept, this header being public API.
 * `InvalidRequestBException` is the one row with no counterpart in the Bridge's table; it is kept for the
 * same reason.
 *
 * The two lists stay defined after this header, unlike the macros it declares with: the RPC layer expands them
 * again to throw the class belonging to the code it read off the wire. Neither side retypes a code, so the
 * declarations here and that dispatch cannot drift apart.
 */

#include "privmx/endpoint/core/ExceptionMacros.hpp"

namespace privmx {
namespace endpoint {
// clang-format off
namespace server {

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointServerRequestException, "Invalid request exception", "Server request", 0xFFFF)

#define SERVER_REQUEST_EXCEPTIONS(X)                                                                                  \
    X(ParseErrorException, "Parse error", 0x8044)                                                                     \
    X(InvalidRequestAException, "Invalid Request", 0x80A8)                                                            \
    X(MethodNotFoundException, "Method not found", 0x80A7)                                                            \
    X(InvalidParamsException, "Invalid params", 0x80A6)                                                               \
    X(InternalErrorException, "Internal error", 0x80A5)                                                               \
    X(InvalidRequestBException, "Invalid request", 0x80A4)                                                            \
    X(InvalidRequestCException, "Only post method allowed", 0x80A3)

#define PRIVMX_SERVER_REQUEST_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointServerRequestException, NAME, MSG, CODE)
SERVER_REQUEST_EXCEPTIONS(PRIVMX_SERVER_REQUEST_DECLARE)
#undef PRIVMX_SERVER_REQUEST_DECLARE

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointServerException, "Unknown server exception", "Server", 0xF000)

#define SERVER_EXCEPTIONS(X)                                                                                          \
    X(InvalidUsernameException, "Invalid username", 0x0002)                                                           \
    X(InvalidSignatureException, "Invalid signature", 0x0008)                                                         \
    X(UserDoesNotExistException, "User doesn't exist", 0x0009)                                                        \
    X(UnknownSessionException, "Unknown session", 0x000C)                                                             \
    X(InvalidSessionStateException, "Invalid session state", 0x000D)                                                  \
    X(InvalidAException, "Invalid A", 0x000E)                                                                         \
    X(DifferentM1Exception, "Different M1", 0x000F)                                                                   \
    X(InvalidTokenException, "Invalid token", 0x0015)                                                                 \
    X(InvalidTimestampException, "Invalid timestamp", 0x0028)                                                         \
    X(InvalidNonceException, "Invalid nonce", 0x0029)                                                                 \
    X(AccessDeniedException, "Access denied", 0x0030)                                                                 \
    X(LoginRejectedException, "Login rejected", 0x0040)                                                               \
    X(InvalidVersionException, "Invalid version", 0x0063)                                                             \
    X(InvalidDeviceIdException, "Invalid device id", 0x0064)                                                          \
    X(PubKeyAlreadyInUseException, "Pub key already in use", 0x0065)                                                  \
    X(MaintenanceModeException, "Maintenance mode", 0x0068)                                                           \
    X(InvalidProxySessionException, "Invalid proxy session", 0x0069)                                                  \
    X(InvalidKeyException, "Invalid key", 0x0070)                                                                     \
    X(WebsocketRequiredException, "Websocket required", 0x0072)                                                       \
    X(WebsocketAlreadyAuthorizedException, "Websocket already authorized", 0x0073)                                    \
    X(Need2FaAuthenticationException, "Need 2FA authentication", 0x0081)                                              \
    X(ExceededLimitOfWebsocketChannelsException, "Exceeded limit of websocket channels", 0x0085)                      \
    X(AddWsChannelIdRequiredOnMultiChannelWebsocketException,                                                         \
      "AddWsChannelId required on multi channel websocket", 0x0086)                                                   \
    X(CannotAddChannelToSingleChannelWebsocketException,                                                              \
      "Cannot add channel to single channel websocket", 0x0087)                                                       \
    X(ThreadDoesNotExistException, "Thread does not exist", 0x6001)                                                   \
    X(InvalidThreadKeyException, "Invalid thread key", 0x6002)                                                        \
    X(RequestDoesNotExistException, "Request does not exist", 0x6003)                                                 \
    X(RequestFileDoesNotExistException, "Request file does not exist", 0x6004)                                        \
    X(RequestFileAlreadyClosedException, "Request file aready closed", 0x6005)                                        \
    X(RequestSizeExceededException, "Request size exceeded", 0x6006)                                                  \
    X(RequestFileSizeExceededException, "Request file size exceeded", 0x6007)                                         \
    X(TooManyFilesInRequestException, "Too many files in request", 0x6008)                                            \
    X(RequestFileDesynchronizedException, "Request file desynchronized", 0x6009)                                      \
    X(InvalidFileIndexException, "Invalid file index", 0x600A)                                                        \
    X(FileAlreadyUsedException, "File already used", 0x600B)                                                          \
    X(RequestNotReadyYetException, "Request not ready yet", 0x600C)                                                   \
    X(ThreadMessageDoesNotExistException, "Thread message does not exist", 0x600D)                                    \
    X(ContainerGroupEpochOutdatedException,                                                                           \
      "Container group key epoch is outdated; call rotate*Keys first", 0x600E)                                        \
    X(ContainerRotatedAlreadyException, "Container keys were already rotated by a concurrent request", 0x600F)        \
    X(InvalidKeyIdException, "Invalid key id", 0x6015)                                                                \
    X(FilesContainerFileHasNotThumbException, "Files container file has not thumb", 0x6105)                           \
    X(UnsupportedOperationException, "Unsupported operation", 0x6115)                                                 \
    X(ContextDoesNotExistException, "Context does not exist", 0x6116)                                                 \
    X(StoreDoesNotExistException, "Store does not exist", 0x6117)                                                     \
    X(StoreFileDoesNotExistException, "Store file does not exist", 0x6118)                                            \
    X(UnsupportedResourceTypeException, "Unsupported resource type", 0x6119)                                          \
    X(ResourceDoesNotExistException, "Resource does not exist", 0x611A)                                               \
    X(CannotQueryNotRootResourceException, "Cannot query not root resource", 0x611B)                                  \
    X(CannotQueryRootResourceException, "Cannot query root resource", 0x611C)                                         \
    X(ResourceFieldDoesNotExistException, "Resource field does not exist", 0x611D)                                    \
    X(InboxDoesNotExistException, "Inbox does not exist", 0x611E)                                                     \
    X(NotEnoughFilesInRequestException, "Not enough files in request", 0x611F)                                        \
    X(ThreadBelongsToInboxException, "Thread belongs to inbox", 0x6120)                                               \
    X(StoreBelongsToInboxException, "Store belongs to inbox", 0x6121)                                                 \
    X(StreamRoomDoesNotExistException, "Stream room does not exist", 0x6122)                                          \
    X(NoMatchForLastIdException, "Object with lastId does not exist", 0x6123)                                         \
    X(ResourcesHaveDifferentContextsException, "Resources does not belong to same context", 0x6124)                   \
    X(MessagesBelongsToDifferentThreadsException, "Messages does not belong to same thread", 0x6125)                  \
    X(FilesBelongsToDifferentStoresException, "Files does not belong to same store", 0x6126)                          \
    X(RequestChunkTooSmallException, "Request chunk too small", 0x6127)                                               \
    X(StoreFileVersionMismatchException, "Store file version mismatch", 0x6128)                                       \
    X(FileDoesNotBelongToStoreException, "File does not belong to store", 0x612A)                                     \
    X(ApiKeyDoesNotExistException, "Api key does not exist", 0x612B)                                                  \
    X(InvalidCredentialsException, "Invalid credentials", 0x612C)                                                     \
    X(ApiKeysLimitExceededException, "Api keys limit exceeded", 0x612D)                                               \
    X(InsufficientScopeException, "Insufficient scope", 0x612E)                                                       \
    X(UnauthorizedException, "Unauthorized", 0x612F)                                                                  \
    X(SolutionDoesNotExistException, "Solution does not exist", 0x6130)                                               \
    X(InvalidAclException, "Invalid ACL", 0x6131)                                                                     \
    X(SolutionHasContextsException, "Solution has contexts", 0x6132)                                                  \
    X(CannotAssignPrivateContextException, "Cannot assign private context", 0x6133)                                   \
    X(CannotUnassignContextFromItsParentException, "Cannot unassign context from its parent", 0x6134)                 \
    X(CannotSwitchConnectedContextToPrivateException, "Cannot switch connected context to private", 0x6135)           \
    X(MethodCallableWithWebsocketOnlyException, "Method is callable with websocket only", 0x6136)                     \
    X(UserDoesNotHaveAccessToContainerException, "User does not have access to container", 0x6137)                    \
    X(DuplicateResourceIdException, "Provided ID is already in use", 0x6138)                                          \
    X(TooManyChannelsInSessionException, "Too many channels in this websocket session", 0x6139)                       \
    X(WsSessionDoesNotExistsException, "Websocket session does not exists", 0x613A)                                   \
    X(ResourceIdMissmatchException, "Provided resource ID missmatch object resource ID", 0x613B)                      \
    X(KvdbDoesNotExistException, "Kvdb does not exist", 0x613C)                                                       \
    X(KvdbEntryDoesNotExistException, "Kvdb item does not exist", 0x613D)                                             \
    X(FirstApiKeyAlreadyExistsException, "First api key was already created", 0x613E)                                 \
    X(InitializationTokenMissmatchException, "Initialization token is invalid or not set", 0x613F)                    \
    X(FailedToSendMediaEventException, "Failed to send Janus Event - no session found", 0x6200)                       \
    X(NotSubscribedForStreamsException, "Failed to leave streams - no session found", 0x6201)                         \
    X(NotConnectedToTheRoomException,                                                                                 \
      "Failed to subscribe to stream/strams - not connected to the room", 0x6202)                                     \
    X(NoSubscriptionsToModifyException,                                                                               \
      "Failed to modify subscriptions - there is no active subscriber session available", 0x6203)                     \
    X(MediaServerSocketAlreadyClosedException, "Media server socket is already closed", 0x6204)                       \
    X(CannotConnectToMediaServerException, "Cannot connect to media server", 0x6205)                                  \
    X(ErrorDuringRequestToMediaServerException, "Error during sending request to media server", 0x6206)               \
    X(MainMediaSessionForUserMissingException, "There is no main session with Janus created for user", 0x6207)        \
    X(StreamRoomClosedException,                                                                                      \
      "Stream room is closed and no new stream can be published or joined", 0x6208)                                   \
    X(MediaRoomAlreadyExistsException, "A room with this ID already exists on the media server", 0x6209)              \
    X(MediaRoomNotFoundException, "The requested room does not exist on the media server", 0x620A)                    \
    X(MediaRoomFullException, "The media room has reached its maximum capacity", 0x620B)                              \
    X(MediaUserNotFoundException, "The specified user or feed was not found in the room", 0x620C)                     \
    X(MediaUserNotJoinedException, "User is not a participant in this room", 0x620D)                                  \
    X(MediaUnauthorizedException, "Action refused: invalid secret or unauthorized request", 0x620E)                   \
    X(MediaAlreadyPublishingException, "User is already publishing a stream in this room", 0x620F)                    \
    X(MediaServerErrorException, "Media server error", 0x6210)                                                        \
    X(MediaInvalidSdpException, "The media server rejected the provided SDP negotiation", 0x6211)                     \
    X(MediaPluginNotFoundException, "The requested media plugin is not available", 0x6212)                            \
    X(UnknownMediaServerException, "Unknown media server exception", 0x6213)                                          \
    X(MediaUserAlreadyJoinedException, "User has already joined the media room", 0x6214)                              \
    X(MediaFeedNotFoundException, "The specified media feed does not exist", 0x6215)                                  \
    X(MediaInvalidSdpTypeException, "The provided SDP type is invalid or unsupported", 0x6216)                        \
    X(MediaNotPublishingException, "User is not currently publishing a stream", 0x6217)                               \
    X(MediaParticipantIdExistsException, "The provided participant ID is already in use", 0x6218)                     \
    X(GroupDoesNotExistException, "Group does not exist", 0x6219)                                                     \
    X(GroupInUseException, "Group is still a member of a container", 0x621A)                                          \
    X(GroupVersionMismatchException, "Group version mismatch or broken signature chain", 0x621B)                      \
    X(GroupRotatedAlreadyException, "Group key was already rotated by a concurrent request", 0x621C)                  \
    X(GroupRotationRateLimitException, "Group key rotation rate limit exceeded", 0x621D)                              \
    X(GroupTreeInvalidException, "Submitted group key tree is malformed or incomplete", 0x621E)                       \
    X(GroupArchiveInvalidException, "Submitted group key archive rungs are invalid", 0x621F)                          \
    X(GroupHasNoTreeException, "Group is not backed by a key tree", 0x6220)                                           \
    X(GroupMemberLimitExceededException, "Group would exceed the configured member limit", 0x6221)                    \
    X(GroupMetaKeyMismatchException, "Group metadata write must use the current epoch's key", 0x6222)                 \
    X(GroupMetaUnreachableException,                                                                                  \
      "Group metadata entry would become unreadable; rewrite the affected metadata plane first", 0x6223)              \
    X(GroupRosterVersionMismatchException, "Group roster has moved since this change was planned", 0x6224)

#define PRIVMX_SERVER_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointServerException, NAME, MSG, CODE)
SERVER_EXCEPTIONS(PRIVMX_SERVER_DECLARE)
#undef PRIVMX_SERVER_DECLARE

// compile-time guard: codes are collected from the lists above, never retyped
#define PRIVMX_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(::privmx::endpoint::core::exceptionCodesUnique({
    SERVER_REQUEST_EXCEPTIONS(PRIVMX_CODE)
    SERVER_EXCEPTIONS(PRIVMX_CODE)
}), "Duplicate exception code in server scope");
#undef PRIVMX_CODE
// #undef SERVER_REQUEST_EXCEPTIONS
// #undef SERVER_EXCEPTIONS
}
// clang-format on
} // namespace endpoint
} // namespace privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_CONVERTED_EXT_EXCEPTION_HPP_
