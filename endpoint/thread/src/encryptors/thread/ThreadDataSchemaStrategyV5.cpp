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

core::dynamic::EncryptedModuleDataV5 ThreadDataSchemaStrategyV5::getEncryptedData(
    const server::ThreadInfo& model
) const {
    return core::dynamic::EncryptedModuleDataV5::fromJSON(model.data.back().data);
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

Thread ThreadDataSchemaStrategyV5::toLibError(const server::ThreadInfo& thread, int64_t errorCode) const {
    return ThreadDataSchemaMapper::toLibThread(thread, {}, {}, errorCode, ThreadDataSchema::Version::VERSION_5);
}
