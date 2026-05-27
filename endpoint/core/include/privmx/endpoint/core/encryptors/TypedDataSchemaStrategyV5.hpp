/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_TYPEDDATASCHEMASTRATEGYV5_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_TYPEDDATASCHEMASTRATEGYV5_HPP_

#include <privmx/endpoint/core/CoreTypes.hpp>
#include "privmx/endpoint/core/encryptors/TypedDataSchemaStrategyDIO.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<typename TEncryptor, typename TEncryptedData, typename TRawData, typename TServerModel, typename TLibObject>
class TypedDataSchemaStrategyV5 : public TypedDataSchemaStrategyDIO<TServerModel, TRawData, TLibObject> {
public:
    DataIntegrityObject getDIOAndAssertIntegrity(const TEncryptedData& encData) const {
        return _encryptor.getDIOAndAssertIntegrity(encData);
    }

protected:
    virtual TEncryptedData getEncryptedData(const TServerModel& model) const = 0;

    TRawData decrypt(const TServerModel& model, const DecryptedEncKey& encKey) const override final {
        auto encData = getEncryptedData(model);
        if (encKey.statusCode == 0) {
            return _encryptor.decrypt(encData, encKey.key);
        } else {
            auto result = _encryptor.extractPublic(encData);
            result.statusCode = encKey.statusCode;
            return result;
        }
    }

    mutable TEncryptor _encryptor;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_TYPEDDATASCHEMASTRATEGYV5_HPP_
