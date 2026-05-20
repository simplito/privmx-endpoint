/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_MESSAGEDATASCHEMASTRATEGYV5_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_MESSAGEDATASCHEMASTRATEGYV5_HPP_

#include <tuple>

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/TypedDataSchemaStrategy.hpp>

#include "privmx/endpoint/thread/ServerTypes.hpp"
#include "privmx/endpoint/thread/ThreadTypes.hpp"
#include "privmx/endpoint/thread/Types.hpp"
#include "privmx/endpoint/thread/encryptors/message/MessageDataEncryptorV5.hpp"

namespace privmx {
namespace endpoint {
namespace thread {
// clang-format off
class MessageDataSchemaStrategyV5 : public core::TypedDataSchemaStrategy<
    server::Message, 
    DecryptedMessageDataV5, 
    std::tuple<Message, core::DataIntegrityObject>
> {
    // clang-format on
public:
    server::EncryptedMessageDataV5 encrypt(
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const core::Buffer& data,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::string& key,
        const core::DataIntegrityObject& dio
    ) const;
    DecryptedMessageDataV5 decrypt(
        const server::Message& message,
        const core::DecryptedEncKey& encKey
    ) const override;
    std::tuple<Message, core::DataIntegrityObject> convert(
        const server::Message& message,
        const DecryptedMessageDataV5& raw
    ) const override;
    std::tuple<Message, core::DataIntegrityObject> makeErrorResult(
        const server::Message& message,
        int64_t errorCode
    ) const override;
    core::DataIntegrityObject getDIOAndAssertIntegrity(const server::EncryptedMessageDataV5& encData) const;

private:
    mutable MessageDataEncryptorV5 _encryptor;
};

} // namespace thread
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_MESSAGEDATASCHEMASTRATEGYV5_HPP_
