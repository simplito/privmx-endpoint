/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/encryptors/store/StoreDataSchemaStrategyV4.hpp"
#include "privmx/endpoint/store/encryptors/store/StoreDataSchemaMapper.hpp"

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>

#include "privmx/endpoint/store/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

core::DecryptedModuleDataV4 StoreDataSchemaStrategyV4::decrypt(
    const server::Store& store,
    const core::DecryptedEncKey& encKey
) const {
    auto encryptedData = core::dynamic::EncryptedModuleDataV4::fromJSON(store.data.back().data);
    return _encryptor.decrypt(encryptedData, encKey.key);
}

std::tuple<Store, core::DataIntegrityObject> StoreDataSchemaStrategyV4::convert(
    const server::Store& store,
    const core::DecryptedModuleDataV4& raw
) const {
    return {
        StoreDataSchemaMapper::toLibStore(
            store, raw.publicMeta, raw.privateMeta, raw.statusCode, StoreDataSchema::Version::VERSION_4
        ),
        core::DataIntegrityObject{
            .creatorUserId = store.lastModifier,
            .creatorPubKey = raw.authorPubKey,
            .contextId = store.contextId,
            .resourceId = store.resourceId.value_or(""),
            .timestamp = store.lastModificationDate,
            .randomId = std::string(),
            .containerId = std::nullopt,
            .containerResourceId = std::nullopt,
            .bridgeIdentity = std::nullopt
        }
    };
}

std::tuple<Store, core::DataIntegrityObject> StoreDataSchemaStrategyV4::makeErrorResult(
    const server::Store& store,
    int64_t errorCode
) const {
    return {
        StoreDataSchemaMapper::toLibStore(store, {}, {}, errorCode, StoreDataSchema::Version::VERSION_4),
        core::DataIntegrityObject{}
    };
}
