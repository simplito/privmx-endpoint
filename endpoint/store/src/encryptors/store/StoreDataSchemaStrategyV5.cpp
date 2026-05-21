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
#include <privmx/endpoint/core/ExceptionConverter.hpp>

#include "privmx/endpoint/store/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

core::DecryptedModuleDataV5 StoreDataSchemaStrategyV5::decrypt(
    const server::Store& store,
    const core::DecryptedEncKey& encKey
) const {
    auto encryptedData = core::dynamic::EncryptedModuleDataV5::fromJSON(store.data.back().data);
    core::DecryptedModuleDataV5 result;
    if (encKey.statusCode != 0) {
        result = _encryptor.extractPublic(encryptedData);
    } else {
        result = _encryptor.decrypt(encryptedData, encKey.key);
    }
    if (encKey.statusCode != 0) {
        result.statusCode = encKey.statusCode;
    }
    return result;
}

std::tuple<Store, core::DataIntegrityObject> StoreDataSchemaStrategyV5::convert(
    const server::Store& store,
    const core::DecryptedModuleDataV5& raw
) const {
    return {
        StoreDataSchemaMapper::toLibStore(
            store, raw.publicMeta, raw.privateMeta, raw.statusCode, StoreDataSchema::Version::VERSION_5
        ),
        raw.dio
    };
}

std::tuple<Store, core::DataIntegrityObject> StoreDataSchemaStrategyV5::makeErrorResult(
    const server::Store& store,
    int64_t errorCode
) const {
    return {
        StoreDataSchemaMapper::toLibStore(store, {}, {}, errorCode, StoreDataSchema::Version::VERSION_5),
        core::DataIntegrityObject{}
    };
}

core::dynamic::EncryptedModuleDataV5 StoreDataSchemaStrategyV5::encrypt(
    const core::ModuleDataToEncryptV5& data,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::string& key
) const {
    return _encryptor.encrypt(data, userPrivKey, key);
}

core::DataIntegrityObject StoreDataSchemaStrategyV5::getDIOAndAssertIntegrity(
    const core::dynamic::EncryptedModuleDataV5& encData
) const {
    return _encryptor.getDIOAndAssertIntegrity(encData);
}
