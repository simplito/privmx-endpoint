#ifndef _PRIVMXLIB_ENDPOINT_THREAD_THREADDATAENCRYPTORV4_HPP
#define _PRIVMXLIB_ENDPOINT_THREAD_THREADDATAENCRYPTORV4_HPP

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/DataEncryptorV4.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/thread/ThreadTypes.hpp"
#include "privmx/endpoint/thread/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class ThreadDataEncryptorV4 {
public:
    server::EncryptedThreadDataV4 encrypt(const ThreadDataToEncrypt& threadData,
                                        const crypto::PrivateKey& authorPrivateKey,
                                        const std::string& encryptionKey);
    DecryptedThreadData decrypt(const server::EncryptedThreadDataV4& encryptedThreadData,
                                const std::string& encryptionKey);

private:
    void validateVersion(const server::EncryptedThreadDataV4& encryptedThreadData);

    core::DataEncryptorV4 _dataEncryptor;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_THREAD_THREADDATAENCRYPTORV4_HPP
