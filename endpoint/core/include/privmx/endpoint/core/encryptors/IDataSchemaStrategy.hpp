/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_IDATASCHEMASTRATEGY_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_IDATASCHEMASTRATEGY_HPP_

#include <optional>

#include <privmx/endpoint/core/CoreTypes.hpp>

namespace privmx {
namespace endpoint {
namespace core {

template<typename TServerModel, typename TDomainObject>
class IDataSchemaStrategy {
public:
    virtual ~IDataSchemaStrategy() = default;
    // `verifiedDio` is the model's own DIO when the caller already decoded and asserted it. A strategy may use
    // it in place of verifying the same DIO a second time, and must otherwise behave as if it were absent.
    virtual TDomainObject decryptAndConvert(
        const TServerModel& model,
        const DecryptedEncKey& encKey,
        const std::optional<DataIntegrityObject>& verifiedDio
    ) const = 0;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_IDATASCHEMASTRATEGY_HPP_
