/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_TYPEDDATASCHEMASTRATEGYdio_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_TYPEDDATASCHEMASTRATEGYdio_HPP_

#include <tuple>

#include <privmx/endpoint/core/CoreTypes.hpp>
#include "privmx/endpoint/core/encryptors/TypedDataSchemaStrategy.hpp"

namespace privmx {
namespace endpoint {
namespace core {

// Intermediate base for strategies whose domain object is std::tuple<TLibObject, DataIntegrityObject>.
// Provides makeErrorResult as final, delegating to pure virtual toLibError.
template<typename TServerModel, typename TRawData, typename TLibObject>
class TypedDataSchemaStrategyDIO
    : public TypedDataSchemaStrategy<TServerModel, TRawData, std::tuple<TLibObject, DataIntegrityObject>> {
public:
    std::tuple<TLibObject, DataIntegrityObject> makeErrorResult(
        const TServerModel& model,
        int64_t errorCode
    ) const override final {
        return {toLibError(model, errorCode), DataIntegrityObject{}};
    }

    virtual TLibObject toLibError(const TServerModel& model, int64_t errorCode) const = 0;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_TYPEDDATASCHEMASTRATEGYdio_HPP_
