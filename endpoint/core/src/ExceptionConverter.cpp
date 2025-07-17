/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/core/ConvertedExceptions.hpp"

using namespace std;
using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

void ExceptionConverter::rethrowAsCoreException(const privmx::utils::PrivmxException& e) {
    unsigned int code = e.getCode();
    unsigned int code_first_two_bytes = (code & 0xFFFF0000) >> 16;
    unsigned int code_second_two_bytes = (code & 0x0000FFFF);

    switch (code_first_two_bytes) {
        case 0xFFFF:
            // Server Request
            switch (code_second_two_bytes) {
                case 0x8043: // -32700 PARSE_ERROR
                    throw server::ParseErrorException(e.getData());
                case 0x80A8: // -32600 INVALID_REQUEST
                    throw server::InvalidRequestAException(e.getData());
                case 0x80A7: // -32601 METHOD_NOT_FOUND
                    throw server::MethodNotFoundException(e.getData());
                case 0x80A6: // -32602 INVALID_PARAMS
                    throw server::InvalidParamsException(e.getData());
                case 0x80A5: // -32603 INTERNAL_ERROR
                    throw server::InternalErrorException(e.getData());
                case 0x80A4: // -32604 NOT_YET_INSTALLED
                    throw server::InvalidRequestBException(e.getData());
                case 0x80A3: // -32605 ONLY_POST_METHOD_ALLOWED
                    throw server::InvalidRequestCException(e.getData());
                default:
                    throw server::EndpointServerRequestException(e.getData());
            }
        case 0x0000:
            switch (code_second_two_bytes) {
                case 0x0030: // ACCESS_DENIED
                    throw server::AccessDeniedException(e.getData());
                case 0x6001: // THREAD_DOES_NOT_EXIST
                    throw server::ThreadDoesNotExistException(e.getData());
                case 0x600D: // THREAD_MESSAGE_DOES_NOT_EXIST
                    throw server::ThreadMessageDoesNotExistException(e.getData());
                case 0x6116: // CONTEXT_DOES_NOT_EXIST
                    throw server::ContextDoesNotExistException(e.getData());
                case 0x6117: // STORE_DOES_NOT_EXIST
                    throw server::StoreDoesNotExistException(e.getData());
                case 0x6118: // STORE_FILE_DOES_NOT_EXIST
                    throw server::StoreFileDoesNotExistException(e.getData());
                case 0x6128: // STORE_FILE_VERSION_MISMATCH
                    throw server::StoreFileVersionMismatchException(e.getData());
                case 0x611E: // INBOX_DOES_NOT_EXIST
                    throw server::InboxDoesNotExistException(e.getData());
                case 0x613C: // KVDB_DOES_NOT_EXIST
                    throw server::KvdbDoesNotExistException(e.getData());
                case 0x613D: // KVDB_ENTRY_DOES_NOT_EXIST
                    throw server::KvdbEntryDoesNotExistException(e.getData());
            }
            if(code_second_two_bytes >= 0x0001 && code_second_two_bytes <= 0x00A0) {
                throw server::EndpointServerException(e.getData(), e.what(), e.getCode());
            }
            if(code_second_two_bytes >= 0x6001 && code_second_two_bytes <= 0x6FFF) {
                throw server::EndpointServerException(e.getData(), e.what(), e.getCode());
            }
            if(code_second_two_bytes >= 0x7001 && code_second_two_bytes <= 0xF0A0) {
                throw server::EndpointServerException(e.getData(), e.what(), e.getCode());
            }
            if(e.getType() != privmx::utils::PrivmxException::LIBRARY) {
                if(e.getType() == privmx::utils::PrivmxException::ALERT && (std::string)(e.what()) == "User doesn't exist") {
                    throw server::UserDoesNotExistException(e.getData());
                }
                throw server::EndpointServerException((std::string)e.what() + " | " + std::to_string(e.getCode()) + " | " + e.getData());
            }
            break;
        case 0x0001:
            switch (code_second_two_bytes) {
                case 0x0001:
                    throw network::NotConnectedException(e.what());
                case 0x0002:
                    throw network::WebsocketDisconnectedException(e.what());
                case 0x0003:
                    throw network::NoMessageReceivedException(e.what());
                default:
                    throw network::EndpointNotConnectedException(e.what());
            }
        case 0x0002:
            switch (code_second_two_bytes) {
                case 0x0001:
                    throw network::InvalidHttpStatusException(e.what());
                case 0x0002:
                    throw network::UnexpectedServerDataException(e.what());
                default:
                    throw network::EndpointServerException(e.what());
            }
        case 0x0003:
            switch (code_second_two_bytes) {
                case 0x0001:
                    throw internal::CannotStringifyVarException(e.what());
                case 0x0002:
                    throw internal::KeyNotExistException(e.what());
                case 0x0003:
                    throw internal::VarIsNotObjectException(e.what());
                case 0x0004:
                    throw internal::VarIsNotArrayException(e.what());
                case 0x0005:
                    throw internal::InvalidVersionFormatException(e.what());
                default:
                    throw internal::EndpointLibException(e.what());
            }
        case 0x000C:
            throw internal::OperationCancelledException(e.what());
        case 0x000D:
            throw internal::NotImplementedException(e.what());
        case 0x00A1:
            switch (code_second_two_bytes) {
                case 0x0001:
                    throw crypto::UnsupportedKeyFormatException(e.what());
                case 0x0002:
                    throw crypto::EmptyPointException(e.what());
                case 0x0003:
                    throw crypto::InvalidSignatureSizeException(e.what());
                case 0x0004:
                    throw crypto::InvalidSignatureHeaderException(e.what());
                case 0x0005:
                    throw crypto::ECCIsNotInitializedException(e.what());
                case 0x0006:
                    throw crypto::EmptyBNException(e.what());
                case 0x0007:
                    throw crypto::WrongMessageSecurityTagException(e.what());
                case 0x0008:
                    throw crypto::DecryptInvalidKeyLengthException(e.what());
                case 0x0009:
                    throw crypto::MissingIvException(e.what());
                case 0x000A:
                    throw crypto::UnknownDecryptionTypeException(e.what());
                case 0x000B:
                    throw crypto::UnsupportedHashAlgorithmException(e.what());
                case 0x000C:
                    throw crypto::CryptoNotImplementedException(e.what());
                case 0x000D:
                    throw crypto::InvalidStrengthException(e.what());
                case 0x000E:
                    throw crypto::InvalidEntropyException(e.what());
                case 0x000F:
                    throw crypto::InvalidMnemonicException(e.what());
                case 0x0010:
                    throw crypto::InvalidChecksumException(e.what());
                case 0x0011:
                    throw crypto::EncryptInvalidKeyLengthException(e.what());
                case 0x0012:
                    throw crypto::OnlyHmacSHA256WithIvIsSupportedForAES256CBCException(e.what());
                case 0x0013:
                    throw crypto::CannotPassIvToDeterministicAES256CBCHmacSHA256Exception(e.what());
                case 0x0014:
                    throw crypto::XTEAECBEncryptionDoesntSupportHmacAndIvException(e.what());
                case 0x0015:
                    throw crypto::UnsupportedEncryptionAlgorithmException(e.what());
                case 0x0016:
                    throw crypto::MissingRequiredSignatureException(e.what());
                case 0x0017:
                    throw crypto::InvalidFirstByteOfCipherException(e.what());
                case 0x0018:
                    throw crypto::GivenPrivKeyDoesNotMatchException(e.what());
                case 0x0019:
                    throw crypto::UnsupportedAlgorithmException(e.what());
                case 0x001A:
                    throw crypto::UnsupportedVersionException(e.what());
                case 0x001B:
                    throw crypto::IncorrectParamsException(e.what());
                case 0x001C:
                    throw crypto::InvalidHandshakeStateException(e.what());
                case 0x001D:
                    throw crypto::InvalidBNException(e.what());
                case 0x0001E:
                    throw crypto::InvalidM2Exception(e.what());
                case 0x001F:
                    throw crypto::InvalidVersionException(e.what());
                case 0x0020:
                    throw crypto::InvalidParentFingerprintException(e.what());
                case 0x0021:
                    throw crypto::DeriveFromPublicKeyNotImplementedException(e.what());
                case 0x0022:
                    throw crypto::InvalidResultSizeException(e.what());
                case 0x0023:
                    throw crypto::InvalidNetworkException(e.what());
                case 0x0024:
                    throw crypto::InvalidCompressionFlagException(e.what());
                case 0x0025:
                    throw crypto::InvalidWIFPayloadLengthException(e.what());
                case 0x0026:
                    throw crypto::OpenSSLException(e.what());
                case 0x0027:
                    throw crypto::PrivmxDriverCryptoException(e.what());
                case 0x0028:
                    throw crypto::PrivmxDriverEccException(e.what());
                default:
                    throw crypto::EndpointCryptoException(e.what());
            }
        case 0x00A3:
            switch (code_second_two_bytes) {
                case 0x0001:
                    throw crypto::InvalidHostException(e.what());
                case 0x0002:
                    throw crypto::NoCallbackForAdditionalLoginStepException(e.what());
                case 0x0003:
                    throw crypto::UnsupportedEmptyKeystoreException(e.what());
                case 0x0004:
                    throw crypto::DifferentIdentityException(e.what());
                case 0x0005:
                    throw crypto::UnsupportedMasterRecordVersionException(e.what());
                case 0x0006:
                    throw crypto::CannotDecryptLevel2OfMasterRecordException(e.what());
                case 0x0007:
                    throw crypto::RpcProxyRequestNotImplementedException(e.what());
                case 0x0008:
                    throw crypto::UserDoesNotExistsException(e.what());
                case 0x0009:
                    throw crypto::SenderCannotBeEmptyException(e.what());
                case 0x000A:
                    throw crypto::SenderMustBeInstanceOfIdentityException(e.what());
                case 0x000B:
                    throw crypto::MessageMustContainsAtLeastOneReceiverException(e.what());
                case 0x000C:
                    throw crypto::InvalidSinkPrivateKeyException(e.what());
                case 0x000D:
                    throw crypto::PrivFsNotImplementedException(e.what());
                case 0x000E:
                    throw crypto::MnemonicIsNotGeneratedYetException(e.what());
                case 0x000F:
                    throw crypto::InvalidResponseException(e.what());
                case 0x0010:
                    throw crypto::UnsupportedPrivDataInfoVersionException(e.what());
                case 0x0011:
                    throw crypto::CosignerKeystoreStateAndUuidAreRequiredException(e.what());
                case 0x0012:
                    throw crypto::ExpectedDocumentsPacketExportClassException(e.what());
                case 0x0013:
                    throw crypto::CannotGetPropertiesFromNonSrpKeySessionConnectionException(e.what());
                case 0x0014:
                    throw crypto::CannotGetUsernameFromNonSrpKeySessionConnectionException(e.what());
                case 0x0015:
                    throw crypto::CannotReloginUserMismatchException(e.what());
                case 0x0016:
                    throw crypto::ConnectionCannotBeRestoredBySessionException(e.what());
                case 0x0017:
                    throw crypto::WorkerRunningException(e.what());
                default:
                    throw crypto::EndpointPrivFsException(e.what());
            }
        case 0x00A4:
            switch (code_second_two_bytes) {
                case 0x0001:
                    throw network::TicketsCountIsEqualZeroException(e.what());
                case 0x0002:
                    throw network::WsConnectException(e.what());
                case 0x0003:
                    throw network::WsSend1Exception(e.what());
                case 0x0004:
                    throw network::WebSocketInvalidPayloadLengthException(e.what());
                case 0x0005:
                    throw network::InvalidWebSocketRequestIdException(e.what());
                case 0x0006:
                    throw network::HttpConnectException(e.what());
                case 0x0007:
                    throw network::HttpRequestException(e.what());
                case 0x0008:
                    throw network::WebSocketPingLoopStoppedException(e.what());
                case 0x0009:
                    throw network::WebSocketPingTimeoutException(e.what());
                case 0x000A:
                    throw network::InvalidHandshakeStateException(e.what());
                case 0x000B:
                    throw network::IncorrectHashmailException(e.what());
                case 0x000C:
                    throw network::UnexpectedEcdhePacketFromServerException(e.what());
                case 0x000D:
                    throw network::UnexpectedEcdhexPacketFromServerException(e.what());
                case 0x000E:
                    throw network::InvalidWsChannelIdException(e.what());
                case 0x000F:
                    throw network::ErrorDuringGettingHTTPChannelException(e.what());
                case 0x0010:
                    throw network::ConnectionDestroyedException(e.what());
                case 0x0011:
                    throw network::SessionLostException(e.what());
                case 0x0012:
                    throw network::ProbeFailException(e.what());
                case 0x0013:
                    throw network::InvalidHostException(e.what());
                case 0x0014:
                    throw network::WebsocketCannotBeMainChannelWhenItIsDisabledException(e.what());
                case 0x0015:
                    throw network::RejectedException(e.what());
                case 0x0016:
                    throw network::FrameHeaderTagsAreNotEqualException(e.what());
                case 0x0017:
                    throw network::UnsupportedFrameVersionException(e.what());
                case 0x0018:
                    throw network::FrameMacsAreNotEqualException(e.what());
                case 0x0019:
                    throw network::InvalidNextReadStateException(e.what());
                case 0x001A:
                    throw network::WriteStateIsNotInitializedException(e.what());
                case 0x001B:
                    throw network::TicketHandshakeErrorException(e.what());
                default:
                    throw network::EndpointRpcException(e.what());
            }
    }
    throw Exception("Unknown exception", "Unknown", "unknown", e.getCode() | 0xE0000000, "Msg: " + (std::string)e.what() + "\nDescription: " + e.getData());
}

core::Exception ExceptionConverter::convert(const privmx::utils::PrivmxException& e) {
    try {
        ExceptionConverter::rethrowAsCoreException(e);
    } catch (const core::Exception &e) {
        return e;
    }
    return core::Exception("Unknown exception", "Unknown", "unknown", e.getCode() | 0xE0000000, "Msg: " + (std::string)e.what() + "\nDescription: " + e.getData());
}

int64_t ExceptionConverter::getCodeOfUserVerificationFailureException() {
    return privmx::endpoint::core::UserVerificationFailureException().getCode();
}