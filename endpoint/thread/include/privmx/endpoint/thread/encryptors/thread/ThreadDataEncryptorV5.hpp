/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_THREADDATAENCRYPTORV5_HPP
#define _PRIVMXLIB_ENDPOINT_THREAD_THREADDATAENCRYPTORV5_HPP

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/DIO/DIOEncryptorV1.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include "privmx/endpoint/thread/ThreadTypes.hpp"
#include "privmx/endpoint/thread/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class ThreadDataEncryptorV5 {
public:
    server::EncryptedThreadDataV5 encrypt(
        const ThreadDataToEncryptV5& threadData,
        const crypto::PrivateKey& authorPrivateKey,
        const std::string& encryptionKey
    );
    DecryptedThreadDataV5 decrypt(const server::EncryptedThreadDataV5& encryptedThreadData, const std::string& encryptionKey);
    core::DataIntegrityObject getDIOAndAssertIntegrity(const server::EncryptedThreadDataV5& encryptedThreadData);
private:
    void assertDataFormat(const server::EncryptedThreadDataV5& encryptedThreadData);
    core::DataEncryptorV4 _dataEncryptor;
    core::DIOEncryptorV1 _DIOEncryptor;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_THREAD_THREADDATAENCRYPTORV5_HPP
