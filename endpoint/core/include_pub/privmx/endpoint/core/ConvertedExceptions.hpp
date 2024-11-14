#ifndef _PRIVMXLIB_ENDPOINT_CONVERTED_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_CONVERTED_EXT_EXCEPTION_HPP_

#include "privmx/endpoint/core/Exception.hpp"

#define DECLARE_SCOPE_ENDPOINT_EXCEPTION(NAME, MSG, SCOPE, CODE, ...)                                            \
    class NAME : public privmx::endpoint::core::Exception {                                                      \
    public:                                                                                                      \
        NAME() : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16)) {}                           \
        NAME(const std::string& description)                                                                     \
            : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16), description) {}                 \
        NAME(const std::string& msg, const std::string& name, unsigned int code)                                 \
            : privmx::endpoint::core::Exception(msg, name, SCOPE, (CODE << 16) | code, std::string()) {}         \
        NAME(const std::string& msg, const std::string& name, unsigned int code, const std::string& description) \
            : privmx::endpoint::core::Exception(msg, name, SCOPE, (CODE << 16) | code, description) {}           \
        void rethrow() const override;                                                                           \
    };                                                                                                           \
    inline void NAME::rethrow() const {                                                                          \
        throw *this;                                                                                             \
    };

#define DECLARE_ENDPOINT_EXCEPTION(BASE_SCOPED, NAME, MSG, CODE, ...)                                            \
    class NAME : public BASE_SCOPED {                                                                            \
    public:                                                                                                      \
        NAME() : BASE_SCOPED(MSG, #NAME, CODE) {}                                                                \
        NAME(const std::string& new_of_description) : BASE_SCOPED(MSG, #NAME, CODE, new_of_description) {}       \
        void rethrow() const override;                                                                           \
    };                                                                                                           \
    inline void NAME::rethrow() const {                                                                          \
        throw *this;                                                                                             \
    };

namespace privmx {
namespace endpoint {

namespace server {

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointServerRequestException, "Invalid request exception", "Server request", 0xFFFF)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerRequestException, ParseErrorException, "Parse error", 0x8043)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerRequestException, InvalidRequestAException, "Invalid request", 0x80A8)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerRequestException, MethodNotFoundException, "Method not found", 0x80A7)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerRequestException, InvalidParamsException, "Invalid params", 0x80A6)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerRequestException, InternalErrorException, "Internal error", 0x80A5)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerRequestException, InvalidRequestBException, "Invalid request", 0x80A4)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerRequestException, InvalidRequestCException, "Invalid request", 0x80A3)

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointServerException, "Unknown server exception", "Server", 0xF000)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerException, UserDoesNotExistException, "User doesn't exist", 0x0009)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerException, AccessDeniedException, "Access denied", 0x0030)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerException, ThreadDoesNotExistException, "Thread does not exist", 0x6001)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerException, ThreadMessageDoesNotExistException, "Thread message does not exist", 0x600D)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerException, ContextDoesNotExistException, "Context does not exist", 0x6116)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerException, StoreDoesNotExistException, "Store does not exist", 0x6117)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerException, StoreFileDoesNotExistException, "Store file does not exist", 0x6118)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerException, InboxDoesNotExistException, "Inbox does not exist", 0x611E)

}

namespace network {

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointNotConnectedException, "Unknown Network Exception", "NetConnection", 0xE001)
DECLARE_ENDPOINT_EXCEPTION(EndpointNotConnectedException, NotConnectedException, "RpcGateway is not connected", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointNotConnectedException, WebsocketDisconnectedException, "Websocket disconnected", 0x0002)

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointServerException, "Unknown Server Exception", "Server", 0xE002)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerException, InvalidHttpStatusException, "Unexpected server data", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointServerException, UnexpectedServerDataException, "Unknown Server Exception", 0x0002)

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointRpcException, "Unknown Rpc exception", "Rpc", 0xE0A4)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, TicketsCountIsEqualZeroException, "Tickets count is equal zero", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, WsConnectException, "wsConnect", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, WsSend1Exception, "WsSend1", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, WebSocketInvalidPayloadLengthException, "Invalid payload length", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, InvalidWebSocketRequestIdException, "Invalid WebSocket request id", 0x0005)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, HttpConnectException, "httpConnect", 0x0006)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, HttpRequestException, "httpRequest", 0x0007)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, WebSocketPingLoopStoppedException, "Ping loop stopped", 0x0008)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, WebSocketPingTimeoutException, "Ping timeout", 0x0009)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, InvalidHandshakeStateException, "Invalid handshake state", 0x000A)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, IncorrectHashmailException, "Incorrect hashmail", 0x000B)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, UnexpectedEcdhePacketFromServerException, "Unexpected ecdhe packet from server", 0x000C)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, UnexpectedEcdhexPacketFromServerException, "Unexpected ecdhex packet from server", 0x000D)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, InvalidWsChannelIdException, "Invalid wsChannelId", 0x000E)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, ErrorDuringGettingHTTPChannelException, "Error during getting HTTP channel", 0x000F)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, ConnectionDestroyedException, "Connection destroyed", 0x0010)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, SessionLostException, "Session lost", 0x0011)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, ProbeFailException, "Probe fail", 0x0012)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, InvalidHostException, "Invalid host", 0x0013)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, WebsocketCannotBeMainChannelWhenItIsDisabledException, "Websocket cannot be main channel when it is disabled", 0x0014)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, RejectedException, "Rejected", 0x0015)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, FrameHeaderTagsAreNotEqualException, "Frame header tags are not equal", 0x0016)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, UnsupportedFrameVersionException, "Unsupported frame version", 0x0017)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, FrameMacsAreNotEqualException, "Frame macs are not equal", 0x0018)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, InvalidNextReadStateException, "Invalid next read state", 0x0019)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, WriteStateIsNotInitializedException, "Write state is not initialized", 0x001A)
DECLARE_ENDPOINT_EXCEPTION(EndpointRpcException, TicketHandshakeErrorException, "Ticket handshake error", 0x001B)

} // network

namespace internal {

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointLibException, "Unknown Lib exception", "Lib", 0xE003)
DECLARE_ENDPOINT_EXCEPTION(EndpointLibException, CannotStringifyVarException, "Cannot stringify var", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointLibException, KeyNotExistException, "Key not exist", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointLibException, VarIsNotObjectException, "Var is not object", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointLibException, VarIsNotArrayException, "Var is not array", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointLibException, OperationCancelledException, "Operation canceled", 0x0005)
DECLARE_ENDPOINT_EXCEPTION(EndpointLibException, NotImplementedException, "Not implemented", 0x0006)

} // internal

namespace crypto {

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointCryptoException, "Unknown Crypto exception", "Crypto", 0xE0A1)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, UnsupportedKeyFormatException, "Unsupported key format", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, EmptyPointException, "Empty point", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidSignatureSizeException, "Invalid signature size", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidSignatureHeaderException, "Invalid signature header", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, ECCIsNotInitializedException, "ECC is not initialized", 0x0005)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, EmptyBNException, "Empty BN", 0x0006)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, WrongMessageSecurityTagException, "Wrong message security tag", 0x0007)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, DecryptInvalidKeyLengthException, "Decrypt invalid key length", 0x0008)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, MissingIvException, "Missing iv", 0x0009)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, UnknownDecryptionTypeException, "Unknown decryption type", 0x000A)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, UnsupportedHashAlgorithmException, "Unsupported hash algorithm", 0x000B)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, CryptoNotImplementedException, "Not implemented", 0x000C)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidStrengthException, "Invalid strength", 0x000D)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidEntropyException, "Invalid entropy", 0x000E)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidMnemonicException, "Invalid mnemonic", 0x000F)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidChecksumException, "Invalid checksum", 0x0010)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, EncryptInvalidKeyLengthException, "Encrypt invalid key length", 0x0011)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, OnlyHmacSHA256WithIvIsSupportedForAES256CBCException, "Only hmac SHA-256 with iv is supported for AES-256-CBC", 0x0012)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, CannotPassIvToDeterministicAES256CBCHmacSHA256Exception, "Cannot pass iv to deterministic AES-256-CBC hmac SHA-256", 0x0014)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, XTEAECBEncryptionDoesntSupportHmacAndIvException, "XTEA-ECB encryption doesn't support hmac and iv", 0x0014)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, UnsupportedEncryptionAlgorithmException, "Unsupported encryption algorithm", 0x0015)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, MissingRequiredSignatureException, "Missing required signature", 0x0016)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidFirstByteOfCipherException, "Invalid first byte of cipher", 0x0017)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, GivenPrivKeyDoesNotMatchException, "Given priv key does not match", 0x0018)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, UnsupportedAlgorithmException, "Unsupported algorithm", 0x0019)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, UnsupportedVersionException, "Unsupported version", 0x001A)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, IncorrectParamsException, "Incorrect params", 0x001B)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidHandshakeStateException, "Invalid handshake state", 0x001C)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidBNException, "Invalid B N", 0x001D)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidM2Exception, "Invalid M2", 0x001E)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidVersionException, "Invalid version", 0x001F)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidParentFingerprintException, "Invalid parent fingerprint", 0x0020)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, DeriveFromPublicKeyNotImplementedException, "Derive from public key not implemented", 0x0021)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidResultSizeException, "Invalid result size", 0x0022)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidNetworkException, "Invalid network", 0x0023)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidCompressionFlagException, "Invalid network", 0x0024)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, InvalidWIFPayloadLengthException, "Invalid WIF payload length", 0x0025)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, OpenSSLException, "OpenSSL Exception", 0x0026)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, PrivmxDriverCryptoException, "privmxDrvCrypto Exception", 0x0027)
DECLARE_ENDPOINT_EXCEPTION(EndpointCryptoException, PrivmxDriverEccException, "privmxDrvEcc Exception", 0x0028)

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointPrivFsException, "Unknown PrivFs exception", "PrivFs", 0xE0A3)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, InvalidHostException, "Invalid host", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, NoCallbackForAdditionalLoginStepException, "No callback for additional login step", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, UnsupportedEmptyKeystoreException, "Unsupported empty keystore", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, DifferentIdentityException, "Different identity", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, UnsupportedMasterRecordVersionException, "Unsupported masterRecord.version", 0x0005)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, CannotDecryptLevel2OfMasterRecordException, "Cannot decrypt level 2 of master record", 0x0006)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, RpcProxyRequestNotImplementedException, "Rpc proxy request not implemented", 0x0007)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, UserDoesNotExistsException, "User does not exists", 0x0008)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, SenderCannotBeEmptyException, "Sender cannot be empty", 0x0009)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, SenderMustBeInstanceOfIdentityException, "Sender must be instance of Identity", 0x000A)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, MessageMustContainsAtLeastOneReceiverException, "Message must contains at least one receiver", 0x000B)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, InvalidSinkPrivateKeyException, "Invalid sink private key", 0x000C)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, PrivFsNotImplementedException, "Not implemented", 0x000D)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, MnemonicIsNotGeneratedYetException, "Mnemonic is not generated yet", 0x000E)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, InvalidResponseException, "INVALID_RESPONSE", 0x000F)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, UnsupportedPrivDataInfoVersionException, "Unsupported privDataInfo version", 0x0010)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, CosignerKeystoreStateAndUuidAreRequiredException, "Cosigner 'keystore', 'state' and 'uuid' are required", 0x0011)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, ExpectedDocumentsPacketExportClassException, "Expected DocumentsPacket export class", 0x0012)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, CannotGetPropertiesFromNonSrpKeySessionConnectionException, "Cannot get properties from non srp/key/session connection", 0x0013)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, CannotGetUsernameFromNonSrpKeySessionConnectionException, "Cannot get username from non srp/key/session connection", 0x0014)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, CannotReloginUserMismatchException,  "Cannot relogin - user mismatch", 0x0015)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, ConnectionCannotBeRestoredBySessionException, "Connection cannot be restored by session", 0x0016)
DECLARE_ENDPOINT_EXCEPTION(EndpointPrivFsException, WorkerRunningException, "Worker running", 0x0017)

} // crypto

} // endpoint
} // privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_CONVERTED_EXT_EXCEPTION_HPP_