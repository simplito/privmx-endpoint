/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_EVENT_EVENTDATASCHEMAMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_EVENTDATASCHEMAMAPPER_HPP_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include <Poco/Dynamic/Var.h>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/VersionStrategyMapper.hpp>

#include "privmx/endpoint/event/Constants.hpp"
#include "privmx/endpoint/event/EventKeyProvider.hpp"
#include "privmx/endpoint/event/EventTypes.hpp"
#include "privmx/endpoint/event/Events.hpp"
#include "privmx/endpoint/event/ServerTypes.hpp"
#include "privmx/endpoint/event/encryptors/event/EventDataEncryptorV5.hpp"
#include "privmx/endpoint/event/encryptors/event/EventDataSchemaStrategyV5.hpp"

namespace privmx {
namespace endpoint {
namespace event {

class EventDataSchemaMapper {
public:
    EventDataSchemaMapper(const privmx::crypto::PrivateKey& userPrivKey, const core::Connection& connection);

    Poco::Dynamic::Var encrypt(
        const std::string& contextId,
        const core::Buffer& data,
        const std::optional<std::string>& type,
        const std::string& key
    );

    ContextCustomEventData decrypt(const server::ContextCustomEventData& rawEvent);
    DecryptedInternalContextEventDataV1 decryptInternal(const server::ContextCustomEventData& rawEvent);

    EventDataSchema::Version getDataStructureVersion(const server::ContextCustomEventData& rawEvent);

private:
    static ContextCustomEventData makeErrorResult(const server::ContextCustomEventData& rawEvent, int64_t errorCode);
    bool verifyDecryptedEventData(const DecryptedEventDataV5& data);

    privmx::crypto::PrivateKey _userPrivKey;
    core::Connection _connection;
    EventKeyProvider _eventKeyProvider;
    core::VersionStrategyMapper<server::ContextCustomEventData, ContextCustomEventData> _strategyMapper;
    std::shared_ptr<EventDataSchemaStrategyV5> _strategyV5;
    EventDataEncryptorV5 _encryptorV5;
};

} // namespace event
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_EVENT_EVENTDATASCHEMAMAPPER_HPP_
