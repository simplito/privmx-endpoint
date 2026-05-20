/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_MESSAGEDATASCHEMAMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_MESSAGEDATASCHEMAMAPPER_HPP_

#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <Poco/Dynamic/Var.h>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/encryptors/VersionStrategyMapper.hpp>

#include "privmx/endpoint/thread/Constants.hpp"
#include "privmx/endpoint/thread/MessageKeyIdFormatValidator.hpp"
#include "privmx/endpoint/thread/ServerTypes.hpp"
#include "privmx/endpoint/thread/Types.hpp"
#include "privmx/endpoint/thread/encryptors/message/MessageDataSchemaStrategyV4.hpp"
#include "privmx/endpoint/thread/encryptors/message/MessageDataSchemaStrategyV5.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class MessageDataSchemaMapper {
public:
    MessageDataSchemaMapper(const privmx::crypto::PrivateKey& userPrivKey, const core::Connection& connection);

    Poco::Dynamic::Var encrypt(
        const std::string& threadId,
        const std::string& resourceId,
        const std::string& contextId,
        const std::string& moduleResourceId,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const core::Buffer& data,
        const core::DecryptedEncKeyV2& msgKey
    );

    std::tuple<Message, core::DataIntegrityObject> decrypt(
        const server::Message& message,
        const core::DecryptedEncKey& encKey
    );

    MessageDataSchema::Version getMessagesDataStructureVersion(const server::Message& message);

    uint32_t validateMessageDataIntegrity(const server::Message& message, const std::string& threadResourceId);

    ThreadDataSchema::Version getMinimumContainerSchemaVersionForMessage(const server::Message& message);

    std::vector<Message> validateDecryptAndConvertMessages(
        std::vector<server::Message> messages,
        const core::ModuleKeys& threadKeys,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );

    Message validateDecryptAndConvertMessage(
        server::Message message,
        const core::ModuleKeys& threadKeys,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );

    static Message toLibMessage(
        const server::Message& message,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const core::Buffer& data,
        const std::string& authorPubKey,
        int64_t statusCode,
        int64_t schemaVersion
    );

private:
    privmx::crypto::PrivateKey _userPrivKey;
    core::Connection _connection;
    MessageKeyIdFormatValidator _messageKeyIdFormatValidator;
    core::VersionStrategyMapper<server::Message, std::tuple<Message, core::DataIntegrityObject>> _strategyMapper;
    std::shared_ptr<MessageDataSchemaStrategyV4> _strategyV4;
    std::shared_ptr<MessageDataSchemaStrategyV5> _strategyV5;
};

} // namespace thread
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_MESSAGEDATASCHEMAMAPPER_HPP_
