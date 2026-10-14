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
// must come last: the header above undefines the declaration macros when it is done with them
#include <privmx/endpoint/core/ExceptionMacros.hpp>

namespace privmx {
namespace privfs {
// clang-format off

DECLARE_SCOPE_ENDPOINT_EXCEPTION(PrivFsException, "Unknown PrivFs exception", "PrivFs", 0xE0A3)

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

#define PRIVMX_PRIVFS_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(PrivFsException, NAME, MSG, CODE)
PRIVFS_EXCEPTIONS(PRIVMX_PRIVFS_DECLARE)
#undef PRIVMX_PRIVFS_DECLARE

// old spelling, kept so the existing throw sites still compile
using NotImplementedException = PrivFsNotImplementedException;

// compile-time guard: codes are collected from the list above, never retyped
#define PRIVMX_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(::privmx::endpoint::core::exceptionCodesUnique({
    PRIVFS_EXCEPTIONS(PRIVMX_CODE)
}), "Duplicate exception code in privfs scope");
#undef PRIVMX_CODE
#undef PRIVFS_EXCEPTIONS
// clang-format on
} // privfs
} // privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_PRIVFS_PRIVFSEXCEPTION_HPP_
