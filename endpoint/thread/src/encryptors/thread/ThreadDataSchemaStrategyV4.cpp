/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/encryptors/thread/ThreadDataSchemaStrategyV4.hpp"
#include "privmx/endpoint/thread/encryptors/thread/ThreadDataSchemaMapper.hpp"

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>

#include "privmx/endpoint/thread/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

core::DecryptedModuleDataV4 ThreadDataSchemaStrategyV4::decrypt(
    const server::ThreadInfo& thread,
    const core::DecryptedEncKey& encKey
) const {
    auto encryptedData = core::dynamic::EncryptedModuleDataV4::fromJSON(thread.data.back().data);
    return _encryptor.decrypt(encryptedData, encKey.key);
}

std::tuple<Thread, core::DataIntegrityObject> ThreadDataSchemaStrategyV4::convert(
    const server::ThreadInfo& thread,
    const core::DecryptedModuleDataV4& raw
) const {
    return {
        ThreadDataSchemaMapper::toLibThread(
            thread, raw.publicMeta, raw.privateMeta, raw.statusCode, ThreadDataSchema::Version::VERSION_4
        ),
        core::DataIntegrityObject{
            .creatorUserId = thread.lastModifier,
            .creatorPubKey = raw.authorPubKey,
            .contextId = thread.contextId,
            .resourceId = thread.resourceId.value_or(""),
            .timestamp = thread.lastModificationDate,
            .randomId = std::string(),
            .containerId = std::nullopt,
            .containerResourceId = std::nullopt,
            .bridgeIdentity = std::nullopt
        }
    };
}

std::tuple<Thread, core::DataIntegrityObject> ThreadDataSchemaStrategyV4::makeErrorResult(
    const server::ThreadInfo& thread,
    int64_t errorCode
) const {
    return {
        ThreadDataSchemaMapper::toLibThread(thread, {}, {}, errorCode, ThreadDataSchema::Version::VERSION_4),
        core::DataIntegrityObject{}
    };
}
