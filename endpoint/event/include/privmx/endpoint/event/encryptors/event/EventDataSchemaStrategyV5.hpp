/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_EVENT_EVENTDATASCHEMASTRATEGYV5_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_EVENTDATASCHEMASTRATEGYV5_HPP_

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/TypedDataSchemaStrategy.hpp>

#include "privmx/endpoint/event/EventTypes.hpp"
#include "privmx/endpoint/event/Events.hpp"
#include "privmx/endpoint/event/ServerTypes.hpp"
#include "privmx/endpoint/event/encryptors/event/EventDataEncryptorV5.hpp"

namespace privmx {
namespace endpoint {
namespace event {

// clang-format off
class EventDataSchemaStrategyV5 : public core::TypedDataSchemaStrategy<
    server::ContextCustomEventData,
    DecryptedEventDataV5,
    ContextCustomEventData
> {
    // clang-format on
public:
    DecryptedEventDataV5 decrypt(
        const server::ContextCustomEventData& model,
        const core::DecryptedEncKey& encKey
    ) const override;
    ContextCustomEventData convert(
        const server::ContextCustomEventData& model,
        const DecryptedEventDataV5& raw
    ) const override;
    ContextCustomEventData makeErrorResult(
        const server::ContextCustomEventData& model,
        int64_t errorCode
    ) const override;

    static ContextCustomEventData toContextCustomEventData(
        const server::ContextCustomEventData& raw,
        const core::Buffer& payload,
        int64_t statusCode,
        int64_t schemaVersion
    );

private:
    mutable EventDataEncryptorV5 _encryptor;
};

} // namespace event
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_EVENT_EVENTDATASCHEMASTRATEGYV5_HPP_
