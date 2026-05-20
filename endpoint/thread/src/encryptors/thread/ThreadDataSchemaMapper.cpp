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
#include <map>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <set>

#include "privmx/endpoint/thread/ThreadException.hpp"
#include <privmx/endpoint/core/Factory.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

ThreadDataSchemaMapper::ThreadDataSchemaMapper(
    const privmx::crypto::PrivateKey& userPrivKey,
    const core::Connection& connection
)
    : _userPrivKey(userPrivKey), _connection(connection) {
    _strategyMapper.registerStrategy(
        ThreadDataSchema::Version::VERSION_4, std::make_shared<ThreadDataSchemaStrategyV4>()
    );
    _strategyV5 = std::make_shared<ThreadDataSchemaStrategyV5>();
    _strategyMapper.registerStrategy(ThreadDataSchema::Version::VERSION_5, _strategyV5);
}

Poco::Dynamic::Var ThreadDataSchemaMapper::encrypt(const core::ModuleDataToEncryptV5& data, const std::string& key) {
    return _strategyV5->encrypt(data, _userPrivKey, key).toJSON();
}

std::tuple<Thread, core::DataIntegrityObject> ThreadDataSchemaMapper::decrypt(
    const server::ThreadInfo& thread,
    const core::DecryptedEncKey& encKey
) {
    auto version = getDataStructureVersion(thread.data.back());
    auto strategy = _strategyMapper.getStrategy(static_cast<int64_t>(version));
    if (!strategy) {
        auto e = UnknowThreadFormatException();
        return {
            toLibThread(thread, {}, {}, e.getCode(), ThreadDataSchema::Version::UNKNOWN), core::DataIntegrityObject{}
        };
    }
    return strategy->decryptAndConvert(thread, encKey);
}

ThreadDataSchema::Version ThreadDataSchemaMapper::getDataStructureVersion(const server::Thread2DataEntry& entry) {
    if (entry.data.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = core::dynamic::VersionedData::fromJSON(entry.data);
        switch (versioned.version) {
        case core::ModuleDataSchema::Version::VERSION_4:
            return ThreadDataSchema::Version::VERSION_4;
        case core::ModuleDataSchema::Version::VERSION_5:
            return ThreadDataSchema::Version::VERSION_5;
        default:
            return ThreadDataSchema::Version::UNKNOWN;
        }
    }
    return ThreadDataSchema::Version::UNKNOWN;
}

void ThreadDataSchemaMapper::assertDataIntegrity(const server::ThreadInfo& thread) {
    const auto& entry = thread.data.back();
    switch (getDataStructureVersion(entry)) {
    case ThreadDataSchema::Version::VERSION_4:
        return;
    case ThreadDataSchema::Version::VERSION_5: {
        auto encData = core::dynamic::EncryptedModuleDataV5::fromJSON(entry.data);
        auto dio = _strategyV5->getDIOAndAssertIntegrity(encData);
        if (dio.contextId != thread.contextId ||
            dio.resourceId != thread.resourceId ||
            dio.creatorUserId != thread.lastModifier ||
            !core::TimestampValidator::validate(dio.timestamp, thread.lastModificationDate)) {
            throw ThreadDataIntegrityException();
        }
        return;
    }
    default:
        throw UnknowThreadFormatException();
    }
    throw UnknowThreadFormatException();
}

uint32_t ThreadDataSchemaMapper::validateDataIntegrity(const server::ThreadInfo& thread) {
    try {
        assertDataIntegrity(thread);
        return 0;
    } catch (const core::Exception& e) { return e.getCode(); } catch (const privmx::utils::PrivmxException& e) {
        return core::ExceptionConverter::convert(e).getCode();
    } catch (...) { return ENDPOINT_CORE_EXCEPTION_CODE; }
}

Thread ThreadDataSchemaMapper::toLibThread(
    const server::ThreadInfo& info,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    int64_t statusCode,
    int64_t schemaVersion
) {
    return Thread{
        .contextId = info.contextId,
        .threadId = info.id,
        .createDate = info.createDate,
        .creator = info.creator,
        .lastModificationDate = info.lastModificationDate,
        .lastModifier = info.lastModifier,
        .users = info.users,
        .managers = info.managers,
        .version = info.version,
        .lastMsgDate = info.lastMsgDate,
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .policy = core::Factory::parsePolicyServerObject(info.policy),
        .messagesCount = info.messages,
        .statusCode = statusCode,
        .schemaVersion = schemaVersion
    };
}

std::vector<Thread> ThreadDataSchemaMapper::validateDecryptAndConvertThreads(
    const std::vector<server::ThreadInfo>& threads,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {

    std::vector<Thread> result(threads.size());
    std::vector<core::DataIntegrityObject> result_dio(threads.size());

    // integrity validation
    for (size_t i = 0; i < threads.size(); i++) {
        auto code = validateDataIntegrity(threads[i]);
        if (code != 0) {
            result[i] = toLibThread(threads[i], {}, {}, code, ThreadDataSchema::Version::UNKNOWN);
        }
    }

    // single batch key fetch
    core::KeyDecryptionAndVerificationRequest keyRequest;
    for (size_t i = 0; i < threads.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        const auto& t = threads[i];
        core::EncKeyLocation loc{.contextId = t.contextId, .resourceId = t.resourceId.value_or("")};
        keyRequest.addOne(t.keys, t.data.back().keyId, loc);
    }
    auto threadKeys = keyProvider->getKeysAndVerify(keyRequest);
    std::set<std::string> seenRandomIds;

    //decrypt, deduplication check
    for (size_t i = 0; i < threads.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        const auto& thread = threads[i];
        core::EncKeyLocation loc{.contextId = thread.contextId, .resourceId = thread.resourceId.value_or("")};
        try {
            auto threadKeysIt = threadKeys.find(
                core::EncKeyLocation{.contextId = thread.contextId, .resourceId = thread.resourceId.value_or("")}
            );
            if (threadKeysIt == threadKeys.end()) {
                throw UnknowThreadFormatException();
            }
            auto [decryptedThread, dio] = decrypt(thread, threadKeysIt->second.at(thread.data.back().keyId));
            result[i] = decryptedThread;
            result_dio[i] = dio;
            if (!seenRandomIds.insert(dio.randomId + "-" + std::to_string(dio.timestamp)).second) {
                result[i].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result[i] = toLibThread(thread, {}, {}, e.getCode(), ThreadDataSchema::Version::UNKNOWN);
        }
    }

    // single batch identity verification
    std::vector<core::VerificationRequest> verifyRequests;
    std::vector<size_t> verifyIndices;
    for (size_t i = 0; i < result.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        verifyRequests.push_back(
            {.contextId = result[i].contextId,
             .senderId = result[i].lastModifier,
             .senderPubKey = result_dio[i].creatorPubKey,
             .date = result[i].lastModificationDate,
             .bridgeIdentity = result_dio[i].bridgeIdentity}
        );
        verifyIndices.push_back(i);
    }
    auto verified = _connection.getImpl()->getUserVerifier()->verify(verifyRequests);
    for (size_t j = 0; j < verifyIndices.size(); j++)
        result[verifyIndices[j]].statusCode = verified[j] ?
            0 :
            core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    return result;
}

Thread ThreadDataSchemaMapper::validateDecryptAndConvertThread(
    const server::ThreadInfo& thread,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return validateDecryptAndConvertThreads({thread}, keyProvider)[0];
}
