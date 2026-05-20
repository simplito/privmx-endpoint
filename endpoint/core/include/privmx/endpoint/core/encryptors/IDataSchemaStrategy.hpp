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

#include <privmx/endpoint/core/CoreTypes.hpp>

namespace privmx {
namespace endpoint {
namespace core {

template<typename TServerModel, typename TDomainObject>
class IDataSchemaStrategy {
public:
    virtual ~IDataSchemaStrategy() = default;
    virtual TDomainObject decryptAndConvert(const TServerModel& model, const DecryptedEncKey& encKey) const = 0;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_IDATASCHEMASTRATEGY_HPP_
