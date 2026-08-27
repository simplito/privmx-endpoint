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
#include "privmx/utils/Utils.hpp"

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
            throw server::ParseErrorException(std::string(e.what()) + "\n" + e.getData());
        case 0x80A8: // -32600 INVALID_REQUEST
            throw server::InvalidRequestAException(std::string(e.what()) + "\n" + e.getData());
        case 0x80A7: // -32601 METHOD_NOT_FOUND
            throw server::MethodNotFoundException(std::string(e.what()) + "\n" + e.getData());
        case 0x80A6: // -32602 INVALID_PARAMS
            throw server::InvalidParamsException(std::string(e.what()) + "\n" + e.getData());
        case 0x80A5: // -32603 INTERNAL_ERROR
            throw server::InternalErrorException(std::string(e.what()) + "\n" + e.getData());
        case 0x80A4: // -32604 NOT_YET_INSTALLED
            throw server::InvalidRequestBException(std::string(e.what()) + "\n" + e.getData());
        case 0x80A3: // -32605 ONLY_POST_METHOD_ALLOWED
            throw server::InvalidRequestCException(std::string(e.what()) + "\n" + e.getData());
        default:
            throw server::EndpointServerRequestException(std::string(e.what()) + "\n" + e.getData());
        }
    case 0x0000:
        switch (code_second_two_bytes) {
        case 0x0030: // ACCESS_DENIED
            throw server::AccessDeniedException(std::string(e.what()) + "\n" + e.getData());
        case 0x0070: // INVALID_KEY
            throw server::InvalidKeyException(std::string(e.what()) + "\n" + e.getData());
        case 0x6001: // THREAD_DOES_NOT_EXIST
            throw server::ThreadDoesNotExistException(std::string(e.what()) + "\n" + e.getData());
        case 0x6002: // INVALID_THREAD_KEY
            throw server::InvalidThreadKeyException(std::string(e.what()) + "\n" + e.getData());
        case 0x600E: // CONTAINER_GROUP_EPOCH_OUTDATED
            throw server::ContainerGroupEpochOutdatedException(std::string(e.what()) + "\n" + e.getData());
        case 0x600F: // CONTAINER_ROTATED_ALREADY
            throw server::ContainerRotatedAlreadyException(std::string(e.what()) + "\n" + e.getData());
        case 0x600D: // THREAD_MESSAGE_DOES_NOT_EXIST
            throw server::ThreadMessageDoesNotExistException(std::string(e.what()) + "\n" + e.getData());
        case 0x6015: // INVALID_KEY_ID
            throw server::InvalidKeyIdException(std::string(e.what()) + "\n" + e.getData());
        case 0x6116: // CONTEXT_DOES_NOT_EXIST
            throw server::ContextDoesNotExistException(std::string(e.what()) + "\n" + e.getData());
        case 0x6117: // STORE_DOES_NOT_EXIST
            throw server::StoreDoesNotExistException(std::string(e.what()) + "\n" + e.getData());
        case 0x6118: // STORE_FILE_DOES_NOT_EXIST
            throw server::StoreFileDoesNotExistException(std::string(e.what()) + "\n" + e.getData());
        case 0x6128: // STORE_FILE_VERSION_MISMATCH
            throw server::StoreFileVersionMismatchException(std::string(e.what()) + "\n" + e.getData());
        case 0x611E: // INBOX_DOES_NOT_EXIST
            throw server::InboxDoesNotExistException(std::string(e.what()) + "\n" + e.getData());
        case 0x613C: // KVDB_DOES_NOT_EXIST
            throw server::KvdbDoesNotExistException(std::string(e.what()) + "\n" + e.getData());
        case 0x613D: // KVDB_ENTRY_DOES_NOT_EXIST
            throw server::KvdbEntryDoesNotExistException(std::string(e.what()) + "\n" + e.getData());
        }
        if (code_second_two_bytes >= 0x0001 && code_second_two_bytes <= 0x00A0) {
            throw server::EndpointServerException(std::string(e.what()) + " | " + e.getData(), e.getCode());
        }
        if (code_second_two_bytes >= 0x6001 && code_second_two_bytes <= 0x6FFF) {
            throw server::EndpointServerException(std::string(e.what()) + " | " + e.getData(), e.getCode());
        }
        if (code_second_two_bytes >= 0x7001 && code_second_two_bytes <= 0xF0A0) {
            throw server::EndpointServerException(std::string(e.what()) + " | " + e.getData(), e.getCode());
        }
        if (e.getType() != privmx::utils::PrivmxException::LIBRARY) {
            if (e.getType() == privmx::utils::PrivmxException::ALERT &&
                (std::string)(e.what()) == "User doesn't exist") {
                throw server::UserDoesNotExistException(std::string(e.what()) + "\n" + e.getData());
            }
            throw server::EndpointServerException(
                (std::string)e.what() + " | " + std::to_string(e.getCode()) + " | " + e.getData()
            );
        }
        break;
    case 0x0001:
        switch (code_second_two_bytes) {
        case 0x0001:
            throw core::NotConnectedException(
                "Reason: " +
                privmx::utils::Hex::from(code_first_two_bytes) +
                "::" +
                privmx::utils::Hex::from(code_second_two_bytes)
            );
        case 0x0002:
            throw network::WebsocketDisconnectedException(std::string(e.what()) + "\n" + e.getData());
        case 0x0003:
            throw network::NoMessageReceivedException(std::string(e.what()) + "\n" + e.getData());
        default:
            throw network::EndpointNotConnectedException(std::string(e.what()) + "-" + e.getData());
        }
    case 0x0002:
        switch (code_second_two_bytes) {
        case 0x0001:
            throw network::InvalidHttpStatusException(std::string(e.what()) + "\n" + e.getData());
        case 0x0002:
            throw network::UnexpectedServerDataException(std::string(e.what()) + "\n" + e.getData());
        default:
            throw network::EndpointServerException(std::string(e.what()) + "-" + e.getData());
        }
    case 0x0003:
        switch (code_second_two_bytes) {
        case 0x0001:
            throw internal::CannotStringifyVarException(std::string(e.what()) + "\n" + e.getData());
        case 0x0002:
            throw internal::KeyNotExistException(std::string(e.what()) + "\n" + e.getData());
        case 0x0003:
            throw internal::VarIsNotObjectException(std::string(e.what()) + "\n" + e.getData());
        case 0x0004:
            throw internal::VarIsNotArrayException(std::string(e.what()) + "\n" + e.getData());
        case 0x0005:
            throw internal::InvalidVersionFormatException(std::string(e.what()) + "\n" + e.getData());
        case 0x0006:
            throw internal::JSONParseException(std::string(e.what()) + "\n" + e.getData());
        default:
            throw internal::EndpointLibException(std::string(e.what()) + "-" + e.getData());
        }
    case 0x000C:
        throw internal::OperationCancelledException(std::string(e.what()) + "\n" + e.getData());
    case 0x000D:
        throw internal::NotImplementedException(std::string(e.what()) + "\n" + e.getData());
    case 0x00A1:
        switch (code_second_two_bytes) {
        case 0x0001:
            throw crypto::UnsupportedKeyFormatException(std::string(e.what()) + "\n" + e.getData());
        case 0x0002:
            throw crypto::EmptyPointException(std::string(e.what()) + "\n" + e.getData());
        case 0x0003:
            throw crypto::InvalidSignatureSizeException(std::string(e.what()) + "\n" + e.getData());
        case 0x0004:
            throw crypto::InvalidSignatureHeaderException(std::string(e.what()) + "\n" + e.getData());
        case 0x0005:
            throw crypto::ECCIsNotInitializedException(std::string(e.what()) + "\n" + e.getData());
        case 0x0006:
            throw crypto::EmptyBNException(std::string(e.what()) + "\n" + e.getData());
        case 0x0007:
            throw crypto::WrongMessageSecurityTagException(std::string(e.what()) + "\n" + e.getData());
        case 0x0008:
            throw crypto::DecryptInvalidKeyLengthException(std::string(e.what()) + "\n" + e.getData());
        case 0x0009:
            throw crypto::MissingIvException(std::string(e.what()) + "\n" + e.getData());
        case 0x000A:
            throw crypto::UnknownDecryptionTypeException(std::string(e.what()) + "\n" + e.getData());
        case 0x000B:
            throw crypto::UnsupportedHashAlgorithmException(std::string(e.what()) + "\n" + e.getData());
        case 0x000C:
            throw crypto::CryptoNotImplementedException(std::string(e.what()) + "\n" + e.getData());
        case 0x000D:
            throw crypto::InvalidStrengthException(std::string(e.what()) + "\n" + e.getData());
        case 0x000E:
            throw crypto::InvalidEntropyException(std::string(e.what()) + "\n" + e.getData());
        case 0x000F:
            throw crypto::InvalidMnemonicException(std::string(e.what()) + "\n" + e.getData());
        case 0x0010:
            throw crypto::InvalidChecksumException(std::string(e.what()) + "\n" + e.getData());
        case 0x0011:
            throw crypto::EncryptInvalidKeyLengthException(std::string(e.what()) + "\n" + e.getData());
        case 0x0012:
            throw crypto::OnlyHmacSHA256WithIvIsSupportedForAES256CBCException(
                std::string(e.what()) + "\n" + e.getData()
            );
        case 0x0013:
            throw crypto::CannotPassIvToDeterministicAES256CBCHmacSHA256Exception(
                std::string(e.what()) + "\n" + e.getData()
            );
        case 0x0014:
            throw crypto::XTEAECBEncryptionDoesntSupportHmacAndIvException(std::string(e.what()) + "\n" + e.getData());
        case 0x0015:
            throw crypto::UnsupportedEncryptionAlgorithmException(std::string(e.what()) + "\n" + e.getData());
        case 0x0016:
            throw crypto::MissingRequiredSignatureException(std::string(e.what()) + "\n" + e.getData());
        case 0x0017:
            throw crypto::InvalidFirstByteOfCipherException(std::string(e.what()) + "\n" + e.getData());
        case 0x0018:
            throw crypto::GivenPrivKeyDoesNotMatchException(std::string(e.what()) + "\n" + e.getData());
        case 0x0019:
            throw crypto::UnsupportedAlgorithmException(std::string(e.what()) + "\n" + e.getData());
        case 0x001A:
            throw crypto::UnsupportedVersionException(std::string(e.what()) + "\n" + e.getData());
        case 0x001B:
            throw crypto::IncorrectParamsException(std::string(e.what()) + "\n" + e.getData());
        case 0x001C:
            throw crypto::InvalidHandshakeStateException(std::string(e.what()) + "\n" + e.getData());
        case 0x001D:
            throw crypto::InvalidBNException(std::string(e.what()) + "\n" + e.getData());
        case 0x0001E:
            throw crypto::InvalidM2Exception(std::string(e.what()) + "\n" + e.getData());
        case 0x001F:
            throw crypto::InvalidVersionException(std::string(e.what()) + "\n" + e.getData());
        case 0x0020:
            throw crypto::InvalidParentFingerprintException(std::string(e.what()) + "\n" + e.getData());
        case 0x0022:
            throw crypto::InvalidResultSizeException(std::string(e.what()) + "\n" + e.getData());
        case 0x0023:
            throw crypto::InvalidNetworkException(std::string(e.what()) + "\n" + e.getData());
        case 0x0024:
            throw crypto::InvalidCompressionFlagException(std::string(e.what()) + "\n" + e.getData());
        case 0x0025:
            throw crypto::InvalidWIFPayloadLengthException(std::string(e.what()) + "\n" + e.getData());
        case 0x0026:
            throw crypto::OpenSSLException(std::string(e.what()) + "\n" + e.getData());
        case 0x0027:
            throw crypto::PrivmxDriverCryptoException(std::string(e.what()) + "\n" + e.getData());
        case 0x0028:
            throw crypto::PrivmxDriverEccException(std::string(e.what()) + "\n" + e.getData());
        case 0x0029:
            throw crypto::GivenPublicKeyDoesNotMatchWithSignatureException(std::string(e.what()) + "\n" + e.getData());
        case 0x002A:
            throw crypto::ExtKeyDoesNotHoldPrivateKeyException(std::string(e.what()) + "\n" + e.getData());
        default:
            throw crypto::EndpointCryptoException(std::string(e.what()) + "-" + e.getData());
        }
    case 0x00A3:
        switch (code_second_two_bytes) {
        case 0x0001:
            throw crypto::InvalidHostException(std::string(e.what()) + "\n" + e.getData());
        case 0x0002:
            throw crypto::NoCallbackForAdditionalLoginStepException(std::string(e.what()) + "\n" + e.getData());
        case 0x0003:
            throw crypto::UnsupportedEmptyKeystoreException(std::string(e.what()) + "\n" + e.getData());
        case 0x0004:
            throw crypto::DifferentIdentityException(std::string(e.what()) + "\n" + e.getData());
        case 0x0005:
            throw crypto::UnsupportedMasterRecordVersionException(std::string(e.what()) + "\n" + e.getData());
        case 0x0006:
            throw crypto::CannotDecryptLevel2OfMasterRecordException(std::string(e.what()) + "\n" + e.getData());
        case 0x0007:
            throw crypto::RpcProxyRequestNotImplementedException(std::string(e.what()) + "\n" + e.getData());
        case 0x0008:
            throw crypto::UserDoesNotExistsException(std::string(e.what()) + "\n" + e.getData());
        case 0x0009:
            throw crypto::SenderCannotBeEmptyException(std::string(e.what()) + "\n" + e.getData());
        case 0x000A:
            throw crypto::SenderMustBeInstanceOfIdentityException(std::string(e.what()) + "\n" + e.getData());
        case 0x000B:
            throw crypto::MessageMustContainsAtLeastOneReceiverException(std::string(e.what()) + "\n" + e.getData());
        case 0x000C:
            throw crypto::InvalidSinkPrivateKeyException(std::string(e.what()) + "\n" + e.getData());
        case 0x000D:
            throw crypto::PrivFsNotImplementedException(std::string(e.what()) + "\n" + e.getData());
        case 0x000E:
            throw crypto::MnemonicIsNotGeneratedYetException(std::string(e.what()) + "\n" + e.getData());
        case 0x000F:
            throw crypto::InvalidResponseException(std::string(e.what()) + "\n" + e.getData());
        case 0x0010:
            throw crypto::UnsupportedPrivDataInfoVersionException(std::string(e.what()) + "\n" + e.getData());
        case 0x0011:
            throw crypto::CosignerKeystoreStateAndUuidAreRequiredException(std::string(e.what()) + "\n" + e.getData());
        case 0x0012:
            throw crypto::ExpectedDocumentsPacketExportClassException(std::string(e.what()) + "\n" + e.getData());
        case 0x0013:
            throw crypto::CannotGetPropertiesFromNonSrpKeySessionConnectionException(
                std::string(e.what()) + "\n" + e.getData()
            );
        case 0x0014:
            throw crypto::CannotGetUsernameFromNonSrpKeySessionConnectionException(
                std::string(e.what()) + "\n" + e.getData()
            );
        case 0x0015:
            throw crypto::CannotReloginUserMismatchException(std::string(e.what()) + "\n" + e.getData());
        case 0x0016:
            throw crypto::ConnectionCannotBeRestoredBySessionException(std::string(e.what()) + "\n" + e.getData());
        case 0x0017:
            throw crypto::WorkerRunningException(std::string(e.what()) + "\n" + e.getData());
        default:
            throw crypto::EndpointPrivFsException(std::string(e.what()) + "-" + "-" + e.getData());
        }
    case 0x00A4:
        switch (code_second_two_bytes) {
        case 0x0001:
            throw core::NotConnectedException(
                "Reason: " +
                privmx::utils::Hex::from(code_first_two_bytes) +
                "::" +
                privmx::utils::Hex::from(code_second_two_bytes)
            );
        case 0x0002:
            throw network::WsConnectException(std::string(e.what()) + "\n" + e.getData());
        case 0x0003:
            throw network::WsSend1Exception(std::string(e.what()) + "\n" + e.getData());
        case 0x0004:
            throw network::WebSocketInvalidPayloadLengthException(std::string(e.what()) + "\n" + e.getData());
        case 0x0005:
            throw network::InvalidWebSocketRequestIdException(std::string(e.what()) + "\n" + e.getData());
        case 0x0006:
            throw network::HttpConnectException(std::string(e.what()) + "\n" + e.getData());
        case 0x0007:
            throw network::HttpRequestException(std::string(e.what()) + "\n" + e.getData());
        case 0x0008:
            throw network::WebSocketPingLoopStoppedException(std::string(e.what()) + "\n" + e.getData());
        case 0x0009:
            throw network::WebSocketPingTimeoutException(std::string(e.what()) + "\n" + e.getData());
        case 0x000A:
            throw network::InvalidHandshakeStateException(std::string(e.what()) + "\n" + e.getData());
        case 0x000B:
            throw network::IncorrectHashmailException(std::string(e.what()) + "\n" + e.getData());
        case 0x000C:
            throw network::UnexpectedEcdhePacketFromServerException(std::string(e.what()) + "\n" + e.getData());
        case 0x000D:
            throw network::UnexpectedEcdhexPacketFromServerException(std::string(e.what()) + "\n" + e.getData());
        case 0x000E:
            throw network::InvalidWsChannelIdException(std::string(e.what()) + "\n" + e.getData());
        case 0x000F:
            throw network::ErrorDuringGettingHTTPChannelException(std::string(e.what()) + "\n" + e.getData());
        case 0x0010:
            throw network::ConnectionDestroyedException(std::string(e.what()) + "\n" + e.getData());
        case 0x0011:
            throw network::SessionLostException(std::string(e.what()) + "\n" + e.getData());
        case 0x0012:
            throw network::ProbeFailException(std::string(e.what()) + "\n" + e.getData());
        case 0x0013:
            throw network::InvalidHostException(std::string(e.what()) + "\n" + e.getData());
        case 0x0014:
            throw network::WebsocketCannotBeMainChannelWhenItIsDisabledException(
                std::string(e.what()) + "\n" + e.getData()
            );
        case 0x0015:
            throw network::RejectedException(std::string(e.what()) + "\n" + e.getData());
        case 0x0016:
            throw network::FrameHeaderTagsAreNotEqualException(std::string(e.what()) + "\n" + e.getData());
        case 0x0017:
            throw network::UnsupportedFrameVersionException(std::string(e.what()) + "\n" + e.getData());
        case 0x0018:
            throw network::FrameMacsAreNotEqualException(std::string(e.what()) + "\n" + e.getData());
        case 0x0019:
            throw network::InvalidNextReadStateException(std::string(e.what()) + "\n" + e.getData());
        case 0x001A:
            throw network::WriteStateIsNotInitializedException(std::string(e.what()) + "\n" + e.getData());
        case 0x001B:
            throw network::TicketHandshakeErrorException(std::string(e.what()) + "\n" + e.getData());
        default:
            throw network::EndpointRpcException(std::string(e.what()) + "-" + e.getData());
        }
    }
    throw Exception(
        "Unknown exception", "Unknown", "unknown", e.getCode() | 0xE0000000,
        "Msg: " + (std::string)e.what() + "\nDescription: " + e.getData()
    );
}

core::Exception ExceptionConverter::convert(const privmx::utils::PrivmxException& e) {
    try {
        ExceptionConverter::rethrowAsCoreException(e);
    } catch (const core::Exception& e) { return e; }
    return core::Exception(
        "Unknown exception", "Unknown", "unknown", e.getCode() | 0xE0000000,
        "Msg: " + (std::string)e.what() + "\nDescription: " + e.getData()
    );
}

int64_t ExceptionConverter::getCodeOfUserVerificationFailureException() {
    return privmx::endpoint::core::UserVerificationFailureException().getCode();
}