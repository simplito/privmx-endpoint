/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/encryptors/thread/ThreadDataSchemaMapper.hpp"

#include <Poco/JSON/Object.h>
#include <privmx/endpoint/core/Factory.hpp>
#include <privmx/endpoint/core/encryptors/DataSchemaMapperUtils.hpp>

#include "privmx/endpoint/thread/ThreadException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

ThreadDataSchemaMapper::ThreadDataSchemaMapper(
    const privmx::crypto::PrivateKey& userPrivKey,
    const core::Connection& connection
)
    : core::BaseModuleDataSchemaMapper(userPrivKey, connection) {
    _strategyMapper.registerStrategy(
        core::ModuleDataSchema::Version::VERSION_4, std::make_shared<ThreadDataSchemaStrategyV4>()
    );
    _strategyV5 = std::make_shared<ThreadDataSchemaStrategyV5>();
    _strategyMapper.registerStrategy(core::ModuleDataSchema::Version::VERSION_5, _strategyV5);
}

Poco::Dynamic::Var ThreadDataSchemaMapper::encrypt(const core::ModuleDataToEncryptV5& data, const std::string& key) {
    return _strategyV5->encrypt(data, _userPrivKey, key).toJSON();
}

std::tuple<Thread, core::DataIntegrityObject> ThreadDataSchemaMapper::decrypt(
    const server::ThreadInfo& thread,
    const core::DecryptedEncKey& encKey
) {
    return _strategyMapper.dispatch(
        static_cast<int64_t>(getDataStructureVersion(thread.data.back())), thread, encKey,
        [&]() -> std::tuple<Thread, core::DataIntegrityObject> {
            return {
                toLibThread(
                    thread, {}, {}, UnknowThreadFormatException().getCode(), ThreadDataSchema::Version::UNKNOWN
                ),
                {}
            };
        }
    );
}

void ThreadDataSchemaMapper::assertDataIntegrity(const server::ThreadInfo& thread) {
    const auto& entry = thread.data.back();
    switch (getDataStructureVersion(entry)) {
    case core::ModuleDataSchema::Version::UNKNOWN:
        throw UnknowThreadFormatException();
    case core::ModuleDataSchema::Version::VERSION_4:
        return;
    case core::ModuleDataSchema::Version::VERSION_5: {
        core::DataSchemaMapperUtils::assertContainerV5DIOIntegrity(entry.data, thread, _strategyV5, [] {
            throw ThreadDataIntegrityException();
        });
        return;
    }
    default:
        throw UnknowThreadFormatException();
    }
}

uint32_t ThreadDataSchemaMapper::validateDataIntegrity(const server::ThreadInfo& thread) {
    return core::DataSchemaMapperUtils::toStatusCode([&] { assertDataIntegrity(thread); });
}

Thread ThreadDataSchemaMapper::toLibThread(
    const server::ThreadInfo& info,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    int64_t statusCode,
    int64_t schemaVersion
) {
    std::vector<core::GroupGrant> groups;
    for (const auto& g : info.groups) {
        groups.push_back({.groupId = g.groupId, .role = g.role});
    }
    return Thread{
        .contextId = info.contextId,
        .threadId = info.id,
        .createDate = info.createDate,
        .creator = info.creator,
        .lastModificationDate = info.lastModificationDate,
        .lastModifier = info.lastModifier,
        .keeper = info.keeper,
        .users = info.users,
        .managers = info.managers,
        .version = info.version,
        .lastMsgDate = info.lastMsgDate,
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .policy = core::Factory::parsePolicyServerObject(info.policy),
        .messagesCount = info.messages,
        .statusCode = statusCode,
        .schemaVersion = schemaVersion,
        .groups = std::move(groups)
    };
}

std::vector<Thread> ThreadDataSchemaMapper::validateDecryptAndConvertThreads(
    const std::vector<server::ThreadInfo>& threads,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return core::DataSchemaMapperUtils::batchValidateDecryptVerifyContainers<Thread>(
        threads, keyProvider, _connection, [&](const server::ThreadInfo& t) { return validateDataIntegrity(t); },
        [](const server::ThreadInfo& t) -> core::EncKeyLocation {
            return {.contextId = t.contextId, .resourceId = t.resourceId.value_or("")};
        },
        [&](const server::ThreadInfo& t, const core::DecryptedEncKey& key) { return decrypt(t, key); },
        [](const server::ThreadInfo& t, uint32_t code) {
            return toLibThread(t, {}, {}, code, ThreadDataSchema::Version::UNKNOWN);
        }
    );
}

Thread ThreadDataSchemaMapper::validateDecryptAndConvertThread(
    const server::ThreadInfo& thread,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return validateDecryptAndConvertThreads({thread}, keyProvider)[0];
}

