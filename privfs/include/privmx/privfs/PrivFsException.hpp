/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_PRIVFS_PRIVFSEXCEPTION_HPP_
#define _PRIVMXLIB_PRIVFS_PRIVFSEXCEPTION_HPP_

#include <privmx/utils/PrivmxExtExceptions.hpp>

namespace privmx {
namespace privfs {

DECLARE_PRIVMX_EXCEPTION(PrivFsException, utils::BaseException, "PrivFs error", 0x00A3)

DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidHostException, PrivFsException, "Invalid host", 0x0001)
DECLARE_PRIVMX_EXCEPTION_CHILD(NoCallbackForAdditionalLoginStepException, PrivFsException, "No callback for additional login step", 0x0002)
DECLARE_PRIVMX_EXCEPTION_CHILD(UnsupportedEmptyKeystoreException, PrivFsException, "Unsupported empty keystore", 0x0003)
DECLARE_PRIVMX_EXCEPTION_CHILD(DifferentIdentityException, PrivFsException, "Different identity", 0x0004)
DECLARE_PRIVMX_EXCEPTION_CHILD(UnsupportedMasterRecordVersionException, PrivFsException, "Unsupported masterRecord.version", 0x0005)
DECLARE_PRIVMX_EXCEPTION_CHILD(CannotDecryptLevel2OfMasterRecordException, PrivFsException, "Cannot decrypt level 2 of master record", 0x0006)
DECLARE_PRIVMX_EXCEPTION_CHILD(RpcProxyRequestNotImplementedException, PrivFsException, "Rpc proxy request not implemented", 0x0007)
DECLARE_PRIVMX_EXCEPTION_CHILD(UserDoesNotExistsException, PrivFsException, "User does not exists", 0x0008)
DECLARE_PRIVMX_EXCEPTION_CHILD(SenderCannotBeEmptyException, PrivFsException, "Sender cannot be empty", 0x0009)
DECLARE_PRIVMX_EXCEPTION_CHILD(SenderMustBeInstanceOfIdentityException, PrivFsException, "Sender must be instance of Identity", 0x000A)
DECLARE_PRIVMX_EXCEPTION_CHILD(MessageMustContainsAtLeastOneReceiverException, PrivFsException, "Message must contains at least one receiver", 0x000B)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidSinkPrivateKeyException, PrivFsException, "Invalid sink private key", 0x000C)
DECLARE_PRIVMX_EXCEPTION_CHILD(NotImplementedException, PrivFsException, "Not implemented", 0x000D)
DECLARE_PRIVMX_EXCEPTION_CHILD(MnemonicIsNotGeneratedYetException, PrivFsException, "Mnemonic is not generated yet", 0x000E)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidResponseException, PrivFsException, "INVALID_RESPONSE", 0x000F)
DECLARE_PRIVMX_EXCEPTION_CHILD(UnsupportedPrivDataInfoVersionException, PrivFsException, "Unsupported privDataInfo version", 0x0010)
DECLARE_PRIVMX_EXCEPTION_CHILD(CosignerKeystoreStateAndUuidAreRequiredException, PrivFsException, "Cosigner 'keystore', 'state' and 'uuid' are required", 0x0011)
DECLARE_PRIVMX_EXCEPTION_CHILD(ExpectedDocumentsPacketExportClassException, PrivFsException, "Expected DocumentsPacket export class", 0x0012)
DECLARE_PRIVMX_EXCEPTION_CHILD(CannotGetPropertiesFromNonSrpKeySessionConnectionException, PrivFsException, "Cannot get properties from non srp/key/session connection", 0x0013)
DECLARE_PRIVMX_EXCEPTION_CHILD(CannotGetUsernameFromNonSrpKeySessionConnectionException, PrivFsException, "Cannot get username from non srp/key/session connection", 0x0014)
DECLARE_PRIVMX_EXCEPTION_CHILD(CannotReloginUserMismatchException, PrivFsException, "Cannot relogin - user mismatch", 0x0015)
DECLARE_PRIVMX_EXCEPTION_CHILD(ConnectionCannotBeRestoredBySessionException, PrivFsException, "Connection cannot be restored by session", 0x0016)
DECLARE_PRIVMX_EXCEPTION_CHILD(WorkerRunningException, PrivFsException, "Worker running", 0x0017)


} // privfs
} // privmx

#endif // _PRIVMXLIB_PRIVFS_PRIVFSEXCEPTION_HPP_
