/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/encryptors/thread/ThreadDataSchemaStrategyV5.hpp"
#include "privmx/endpoint/thread/encryptors/thread/ThreadDataSchemaMapper.hpp"

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>

#include "privmx/endpoint/thread/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

core::dynamic::EncryptedModuleDataV5 ThreadDataSchemaStrategyV5::encrypt(
    const core::ModuleDataToEncryptV5& data,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::string& key
) const {
    return _encryptor.encrypt(data, userPrivKey, key);
}

core::DecryptedModuleDataV5 ThreadDataSchemaStrategyV5::decrypt(
    const server::ThreadInfo& thread,
    const core::DecryptedEncKey& encKey
) const {
    auto encryptedData = core::dynamic::EncryptedModuleDataV5::fromJSON(thread.data.back().data);
    privmx::endpoint::core::DecryptedModuleDataV5 result;
    if (encKey.statusCode == 0) {
        return _encryptor.decrypt(encryptedData, encKey.key);
    } else {
        auto result = _encryptor.extractPublic(encryptedData);
        result.statusCode = encKey.statusCode;
        return result;
    }
}

std::tuple<Thread, core::DataIntegrityObject> ThreadDataSchemaStrategyV5::convert(
    const server::ThreadInfo& thread,
    const core::DecryptedModuleDataV5& raw
) const {
    return {
        ThreadDataSchemaMapper::toLibThread(
            thread, raw.publicMeta, raw.privateMeta, raw.statusCode, ThreadDataSchema::Version::VERSION_5
        ),
        raw.dio
    };
}

std::tuple<Thread, core::DataIntegrityObject> ThreadDataSchemaStrategyV5::makeErrorResult(
    const server::ThreadInfo& thread,
    int64_t errorCode
) const {
    return {
        ThreadDataSchemaMapper::toLibThread(thread, {}, {}, errorCode, ThreadDataSchema::Version::VERSION_5),
        core::DataIntegrityObject{}
    };
}

core::DataIntegrityObject ThreadDataSchemaStrategyV5::getDIOAndAssertIntegrity(
    const core::dynamic::EncryptedModuleDataV5& encData
) const {
    return _encryptor.getDIOAndAssertIntegrity(encData);
}
