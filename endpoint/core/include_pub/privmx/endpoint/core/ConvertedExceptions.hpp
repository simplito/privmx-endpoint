#ifndef _PRIVMXLIB_ENDPOINT_CONVERTED_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_CONVERTED_EXT_EXCEPTION_HPP_

#include "privmx/endpoint/core/Exception.hpp"

#define DECLARE_SCOPE_ENDPOINT_EXCEPTION(NAME, MSG, SCOPE, CODE, ...)                                                  \
    class NAME : public privmx::endpoint::core::Exception {                                                            \
    public:                                                                                                            \
        static constexpr unsigned int SCOPE_CODE = (CODE);                                                             \
        NAME() : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16)) {}                                 \
        NAME(const std::string& description)                                                                           \
            : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16), description) {}                       \
        NAME(const std::string& description, unsigned int code)                                                        \
            : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16) | code, description) {}                \
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
// clang-format off
namespace server {

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointServerRequestException, "Invalid request exception", "Server request", 0xFFFF)

#define SERVER_REQUEST_EXCEPTIONS(X)                                                                                  \
    X(ParseErrorException, "Parse error", 0x8043)                                                                     \
    X(InvalidRequestAException, "Invalid request", 0x80A8)                                                            \
    X(MethodNotFoundException, "Method not found", 0x80A7)                                                            \
    X(InvalidParamsException, "Invalid params", 0x80A6)                                                               \
    X(InternalErrorException, "Internal error", 0x80A5)                                                               \
    X(InvalidRequestBException, "Invalid request", 0x80A4)                                                            \
    X(InvalidRequestCException, "Invalid request", 0x80A3)

#define PRIVMX_SERVER_REQUEST_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointServerRequestException, NAME, MSG, CODE)
SERVER_REQUEST_EXCEPTIONS(PRIVMX_SERVER_REQUEST_DECLARE)
#undef PRIVMX_SERVER_REQUEST_DECLARE

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointServerException, "Unknown server exception", "Server", 0xF000)

#define SERVER_EXCEPTIONS(X)                                                                                          \
    X(UserDoesNotExistException, "User doesn't exist", 0x0009)                                                        \
    X(AccessDeniedException, "Access denied", 0x0030)                                                                 \
    X(InvalidKeyException, "Invalid key", 0x0070)                                                                     \
    X(ThreadDoesNotExistException, "Thread does not exist", 0x6001)                                                   \
    X(InvalidThreadKeyException, "Invalid thread key", 0x6002)                                                        \
    X(ThreadMessageDoesNotExistException, "Thread message does not exist", 0x600D)                                    \
    X(ContainerGroupEpochOutdatedException, "Container group epoch outdated", 0x600E)                                   \
    X(ContainerRotatedAlreadyException, "Container keys were already rotated by a concurrent request", 0x600F)        \
    X(InvalidKeyIdException, "Invalid key id", 0x6015)                                                                \
    X(ContextDoesNotExistException, "Context does not exist", 0x6116)                                                 \
    X(StoreDoesNotExistException, "Store does not exist", 0x6117)                                                     \
    X(StoreFileDoesNotExistException, "Store file does not exist", 0x6118)                                            \
    X(StoreFileVersionMismatchException, "Store file version mismatch", 0x6128)                                       \
    X(InboxDoesNotExistException, "Inbox does not exist", 0x611E)                                                     \
    X(KvdbDoesNotExistException, "Kvdb does not exist", 0x613C)                                                       \
    X(KvdbEntryDoesNotExistException, "Kvdb entry does not exist", 0x613D)

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
#undef SERVER_REQUEST_EXCEPTIONS
#undef SERVER_EXCEPTIONS
}

namespace network {

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointNotConnectedException, "Unknown Network Exception", "NetConnection", 0xE001)

#define NET_EXCEPTIONS(X)                                                                                             \
    X(NotConnectedException, "RpcGateway is not connected", 0x0001)                                                   \
    X(WebsocketDisconnectedException, "Websocket disconnected", 0x0002)                                               \
    X(NoMessageReceivedException, "No message received, http session lost", 0x0003)

#define PRIVMX_NET_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointNotConnectedException, NAME, MSG, CODE)
NET_EXCEPTIONS(PRIVMX_NET_DECLARE)
#undef PRIVMX_NET_DECLARE

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointServerException, "Unknown Server Exception", "Server", 0xE002)

#define NET_SERVER_EXCEPTIONS(X)                                                                                      \
    X(InvalidHttpStatusException, "Unexpected server data", 0x0001)                                                   \
    X(UnexpectedServerDataException, "Unknown Server Exception", 0x0002)

#define PRIVMX_NET_SERVER_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointServerException, NAME, MSG, CODE)
NET_SERVER_EXCEPTIONS(PRIVMX_NET_SERVER_DECLARE)
#undef PRIVMX_NET_SERVER_DECLARE

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointRpcException, "Unknown Rpc exception", "Rpc", 0xE0A4)

#define RPC_EXCEPTIONS(X)                                                                                             \
    X(TicketsCountIsEqualZeroException, "Tickets count is equal zero", 0x0001)                                        \
    X(WsConnectException, "wsConnect", 0x0002)                                                                        \
    X(WsSend1Exception, "WsSend1", 0x0003)                                                                            \
    X(WebSocketInvalidPayloadLengthException, "Invalid payload length", 0x0004)                                       \
    X(InvalidWebSocketRequestIdException, "Invalid WebSocket request id", 0x0005)                                     \
    X(HttpConnectException, "httpConnect", 0x0006)                                                                    \
    X(HttpRequestException, "httpRequest", 0x0007)                                                                    \
    X(WebSocketPingLoopStoppedException, "Ping loop stopped", 0x0008)                                                 \
    X(WebSocketPingTimeoutException, "Ping timeout", 0x0009)                                                          \
    X(InvalidHandshakeStateException, "Invalid handshake state", 0x000A)                                              \
    X(IncorrectHashmailException, "Incorrect hashmail", 0x000B)                                                       \
    X(UnexpectedEcdhePacketFromServerException, "Unexpected ecdhe packet from server", 0x000C)                        \
    X(UnexpectedEcdhexPacketFromServerException, "Unexpected ecdhex packet from server", 0x000D)                      \
    X(InvalidWsChannelIdException, "Invalid wsChannelId", 0x000E)                                                     \
    X(ErrorDuringGettingHTTPChannelException, "Error during getting HTTP channel", 0x000F)                            \
    X(ConnectionDestroyedException, "Connection destroyed", 0x0010)                                                   \
    X(SessionLostException, "Session lost", 0x0011)                                                                   \
    X(ProbeFailException, "Probe fail", 0x0012)                                                                       \
    X(InvalidHostException, "Invalid host", 0x0013)                                                                   \
    X(WebsocketCannotBeMainChannelWhenItIsDisabledException, "Websocket cannot be main channel when it is disabled", 0x0014) \
    X(RejectedException, "Rejected", 0x0015)                                                                          \
    X(FrameHeaderTagsAreNotEqualException, "Frame header tags are not equal", 0x0016)                                 \
    X(UnsupportedFrameVersionException, "Unsupported frame version", 0x0017)                                          \
    X(FrameMacsAreNotEqualException, "Frame macs are not equal", 0x0018)                                              \
    X(InvalidNextReadStateException, "Invalid next read state", 0x0019)                                               \
    X(WriteStateIsNotInitializedException, "Write state is not initialized", 0x001A)                                  \
    X(TicketHandshakeErrorException, "Ticket handshake error", 0x001B)

#define PRIVMX_RPC_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, NAME, MSG, CODE)
RPC_EXCEPTIONS(PRIVMX_RPC_DECLARE)
#undef PRIVMX_RPC_DECLARE

// compile-time guard: codes are collected from the lists above, never retyped
#define PRIVMX_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(::privmx::endpoint::core::exceptionCodesUnique({
    NET_EXCEPTIONS(PRIVMX_CODE)
    NET_SERVER_EXCEPTIONS(PRIVMX_CODE)
    RPC_EXCEPTIONS(PRIVMX_CODE)
}), "Duplicate exception code in network scope");
#undef PRIVMX_CODE
#undef NET_EXCEPTIONS
#undef NET_SERVER_EXCEPTIONS
#undef RPC_EXCEPTIONS
} // network

namespace internal {

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointLibException, "Unknown Lib exception", "Lib", 0xE003)

#define LIB_EXCEPTIONS(X)                                                                                             \
    X(CannotStringifyVarException, "Cannot stringify var", 0x0001)                                                    \
    X(KeyNotExistException, "Key not exist", 0x0002)                                                                  \
    X(VarIsNotObjectException, "Var is not object", 0x0003)                                                           \
    X(VarIsNotArrayException, "Var is not array", 0x0004)                                                             \
    X(OperationCancelledException, "Operation canceled", 0x0005)                                                      \
    X(NotImplementedException, "Not implemented", 0x0006)                                                             \
    X(InvalidVersionFormatException, "Invalid version format", 0x0007)                                                \
    X(JSONParseException, "Cannot parse JSON", 0x0008)

#define PRIVMX_LIB_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointLibException, NAME, MSG, CODE)
LIB_EXCEPTIONS(PRIVMX_LIB_DECLARE)
#undef PRIVMX_LIB_DECLARE

// compile-time guard: codes are collected from the list above, never retyped
#define PRIVMX_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(::privmx::endpoint::core::exceptionCodesUnique({
    LIB_EXCEPTIONS(PRIVMX_CODE)
}), "Duplicate exception code in internal scope");
#undef PRIVMX_CODE
#undef LIB_EXCEPTIONS
} // internal

namespace crypto {

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointCryptoException, "Unknown Crypto exception", "Crypto", 0xE0A1)

#define CRYPTO_EXCEPTIONS(X)                                                                                          \
    X(UnsupportedKeyFormatException, "Unsupported key format", 0x0001)                                                \
    X(EmptyPointException, "Empty point", 0x0002)                                                                     \
    X(InvalidSignatureSizeException, "Invalid signature size", 0x0003)                                                \
    X(InvalidSignatureHeaderException, "Invalid signature header", 0x0004)                                            \
    X(ECCIsNotInitializedException, "ECC is not initialized", 0x0005)                                                 \
    X(EmptyBNException, "Empty BN", 0x0006)                                                                           \
    X(WrongMessageSecurityTagException, "Wrong message security tag", 0x0007)                                         \
    X(DecryptInvalidKeyLengthException, "Decrypt invalid key length", 0x0008)                                         \
    X(MissingIvException, "Missing iv", 0x0009)                                                                       \
    X(UnknownDecryptionTypeException, "Unknown decryption type", 0x000A)                                              \
    X(UnsupportedHashAlgorithmException, "Unsupported hash algorithm", 0x000B)                                        \
    X(CryptoNotImplementedException, "Not implemented", 0x000C)                                                       \
    X(InvalidStrengthException, "Invalid strength", 0x000D)                                                           \
    X(InvalidEntropyException, "Invalid entropy", 0x000E)                                                             \
    X(InvalidMnemonicException, "Invalid mnemonic", 0x000F)                                                           \
    X(InvalidChecksumException, "Invalid checksum", 0x0010)                                                           \
    X(EncryptInvalidKeyLengthException, "Encrypt invalid key length", 0x0011)                                         \
    X(OnlyHmacSHA256WithIvIsSupportedForAES256CBCException, "Only hmac SHA-256 with iv is supported for AES-256-CBC", 0x0012) \
    X(CannotPassIvToDeterministicAES256CBCHmacSHA256Exception, "Cannot pass iv to deterministic AES-256-CBC hmac SHA-256", 0x0013) \
    X(XTEAECBEncryptionDoesntSupportHmacAndIvException, "XTEA-ECB encryption doesn't support hmac and iv", 0x0014)    \
    X(UnsupportedEncryptionAlgorithmException, "Unsupported encryption algorithm", 0x0015)                            \
    X(MissingRequiredSignatureException, "Missing required signature", 0x0016)                                        \
    X(InvalidFirstByteOfCipherException, "Invalid first byte of cipher", 0x0017)                                      \
    X(GivenPrivKeyDoesNotMatchException, "Given priv key does not match", 0x0018)                                     \
    X(UnsupportedAlgorithmException, "Unsupported algorithm", 0x0019)                                                 \
    X(UnsupportedVersionException, "Unsupported version", 0x001A)                                                     \
    X(IncorrectParamsException, "Incorrect params", 0x001B)                                                           \
    X(InvalidHandshakeStateException, "Invalid handshake state", 0x001C)                                              \
    X(InvalidBNException, "Invalid B N", 0x001D)                                                                      \
    X(InvalidM2Exception, "Invalid M2", 0x001E)                                                                       \
    X(InvalidVersionException, "Invalid version", 0x001F)                                                             \
    X(InvalidParentFingerprintException, "Invalid parent fingerprint", 0x0020)                                        \
    X(InvalidResultSizeException, "Invalid result size", 0x0022)                                                      \
    X(InvalidNetworkException, "Invalid network", 0x0023)                                                             \
    X(InvalidCompressionFlagException, "Invalid network", 0x0024)                                                     \
    X(InvalidWIFPayloadLengthException, "Invalid WIF payload length", 0x0025)                                         \
    X(OpenSSLException, "OpenSSL Exception", 0x0026)                                                                  \
    X(PrivmxDriverCryptoException, "privmxDrvCrypto Exception", 0x0027)                                               \
    X(PrivmxDriverEccException, "privmxDrvEcc Exception", 0x0028)                                                     \
    X(GivenPublicKeyDoesNotMatchWithSignatureException, "DGiven public key does not match with signature", 0x0029)    \
    X(ExtKeyDoesNotHoldPrivateKeyException, "Ext key does not hold private key", 0x002A)

#define PRIVMX_CRYPTO_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, NAME, MSG, CODE)
CRYPTO_EXCEPTIONS(PRIVMX_CRYPTO_DECLARE)
#undef PRIVMX_CRYPTO_DECLARE

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointPrivFsException, "Unknown PrivFs exception", "PrivFs", 0xE0A3)

#define PRIVFS_EXCEPTIONS(X)                                                                                          \
    X(InvalidHostException, "Invalid host", 0x0001)                                                                   \
    X(NoCallbackForAdditionalLoginStepException, "No callback for additional login step", 0x0002)                     \
    X(UnsupportedEmptyKeystoreException, "Unsupported empty keystore", 0x0003)                                        \
    X(DifferentIdentityException, "Different identity", 0x0004)                                                       \
    X(UnsupportedMasterRecordVersionException, "Unsupported masterRecord.version", 0x0005)                            \
    X(CannotDecryptLevel2OfMasterRecordException, "Cannot decrypt level 2 of master record", 0x0006)                  \
    X(RpcProxyRequestNotImplementedException, "Rpc proxy request not implemented", 0x0007)                            \
    X(UserDoesNotExistsException, "User does not exists", 0x0008)                                                     \
    X(SenderCannotBeEmptyException, "Sender cannot be empty", 0x0009)                                                 \
    X(SenderMustBeInstanceOfIdentityException, "Sender must be instance of Identity", 0x000A)                         \
    X(MessageMustContainsAtLeastOneReceiverException, "Message must contains at least one receiver", 0x000B)          \
    X(InvalidSinkPrivateKeyException, "Invalid sink private key", 0x000C)                                             \
    X(PrivFsNotImplementedException, "Not implemented", 0x000D)                                                       \
    X(MnemonicIsNotGeneratedYetException, "Mnemonic is not generated yet", 0x000E)                                    \
    X(InvalidResponseException, "INVALID_RESPONSE", 0x000F)                                                           \
    X(UnsupportedPrivDataInfoVersionException, "Unsupported privDataInfo version", 0x0010)                            \
    X(CosignerKeystoreStateAndUuidAreRequiredException, "Cosigner 'keystore', 'state' and 'uuid' are required", 0x0011) \
    X(ExpectedDocumentsPacketExportClassException, "Expected DocumentsPacket export class", 0x0012)                   \
    X(CannotGetPropertiesFromNonSrpKeySessionConnectionException, "Cannot get properties from non srp/key/session connection", 0x0013) \
    X(CannotGetUsernameFromNonSrpKeySessionConnectionException, "Cannot get username from non srp/key/session connection", 0x0014) \
    X(CannotReloginUserMismatchException, "Cannot relogin - user mismatch", 0x0015)                                   \
    X(ConnectionCannotBeRestoredBySessionException, "Connection cannot be restored by session", 0x0016)               \
    X(WorkerRunningException, "Worker running", 0x0017)

#define PRIVMX_PRIVFS_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, NAME, MSG, CODE)
PRIVFS_EXCEPTIONS(PRIVMX_PRIVFS_DECLARE)
#undef PRIVMX_PRIVFS_DECLARE

// compile-time guard: codes are collected from the lists above, never retyped
#define PRIVMX_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(::privmx::endpoint::core::exceptionCodesUnique({
    CRYPTO_EXCEPTIONS(PRIVMX_CODE)
    PRIVFS_EXCEPTIONS(PRIVMX_CODE)
}), "Duplicate exception code in crypto scope");
#undef PRIVMX_CODE
#undef CRYPTO_EXCEPTIONS
#undef PRIVFS_EXCEPTIONS
} // crypto
// clang-format on
} // namespace endpoint
} // namespace privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_CONVERTED_EXT_EXCEPTION_HPP_
