/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/encryptors/store/StoreDataSchemaStrategyV5.hpp"
#include "privmx/endpoint/store/encryptors/store/StoreDataSchemaMapper.hpp"

#include <privmx/endpoint/core/CoreConstants.hpp>

#include "privmx/endpoint/store/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

core::dynamic::EncryptedModuleDataV5 StoreDataSchemaStrategyV5::getEncryptedData(const server::Store& model) const {
    return core::dynamic::EncryptedModuleDataV5::fromJSON(model.data.back().data);
}

std::tuple<Store, core::DataIntegrityObject> StoreDataSchemaStrategyV5::convert(
    const server::Store& store,
    const core::DecryptedModuleDataV5& raw
) const {
    return {
        StoreDataSchemaMapper::toLibStore(
            store, raw.publicMeta, raw.privateMeta, core::toPublicError(raw.error), StoreDataSchema::Version::VERSION_5
        ),
        raw.dio
    };
}

Store StoreDataSchemaStrategyV5::toLibError(const server::Store& store, const std::optional<core::Error>& error) const {
    return StoreDataSchemaMapper::toLibStore(store, {}, {}, error, StoreDataSchema::Version::VERSION_5);
}

core::dynamic::EncryptedModuleDataV5 StoreDataSchemaStrategyV5::encrypt(
    const core::ModuleDataToEncryptV5& data,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::string& key
) const {
    return _encryptor.encrypt(data, userPrivKey, key);
}
