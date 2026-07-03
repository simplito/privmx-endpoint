/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_TYPEDDATASCHEMASTRATEGY_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_TYPEDDATASCHEMASTRATEGY_HPP_

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>

#include "privmx/endpoint/core/encryptors/IDataSchemaStrategy.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<typename TServerModel, typename TRawData, typename TDomainObject>
class TypedDataSchemaStrategy : public IDataSchemaStrategy<TServerModel, TDomainObject> {
public:
    TDomainObject decryptAndConvert(const TServerModel& model, const DecryptedEncKey& encKey) const override final {
        try {
            return convert(model, decrypt(model, encKey));
        } catch (const core::Exception& e) {
            return makeErrorResult(model, e.getCode());
        } catch (const privmx::utils::PrivmxException& e) {
            return makeErrorResult(model, ExceptionConverter::convert(e).getCode());
        } catch (...) { return makeErrorResult(model, ENDPOINT_CORE_EXCEPTION_CODE); }
    }

    virtual TRawData decrypt(const TServerModel& model, const DecryptedEncKey& encKey) const = 0;
    virtual TDomainObject convert(const TServerModel& model, const TRawData& raw) const = 0;
    virtual TDomainObject makeErrorResult(const TServerModel& model, int64_t errorCode) const = 0;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_TYPEDDATASCHEMASTRATEGY_HPP_
