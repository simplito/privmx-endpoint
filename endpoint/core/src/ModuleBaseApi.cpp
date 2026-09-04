/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>
#include <algorithm>
#include <privmx/utils/Utils.hpp>
#include <set>
#include <type_traits>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>

#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/ModuleBaseApi.hpp"
#include "privmx/endpoint/core/encryptors/EncKey/EncKeyEncryptorV2.hpp"
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/Utils.hpp>
#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>

using namespace privmx::endpoint::core;

ModuleBaseApi::ModuleBaseApi(
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<EventMiddleware>& eventMiddleware,
    const Connection& connection
)
    : _guardedExecutor(std::make_shared<privmx::utils::GuardedExecutor>()), _userPrivKey(userPrivKey),
      _keyProvider(keyProvider), _host(host), _eventMiddleware(eventMiddleware), _connection(connection) {}

void ModuleBaseApi::initGroupResolvers(const std::optional<GroupResolvers>& resolvers) {
    if (!resolvers.has_value()) {
        return;
    }
    _groupPrivKeyResolver = resolvers->groupPrivKey;
    _groupEpochResolver = resolvers->groupEpochs;
}

ModuleBaseApi::ContainerRoster ModuleBaseApi::resolveRosterPubKeys(
    const std::string& contextId,
    const std::vector<std::string>& userIds,
    const std::vector<std::string>& managerIds
) {
    std::set<std::string> wanted(userIds.begin(), userIds.end());
    wanted.insert(managerIds.begin(), managerIds.end());

    std::unordered_map<std::string, std::string> pubKeyByUserId;
    constexpr size_t BRIDGE_MAX_BATCH_SIZE = 100; // The bridge listing caps at 100
    auto it = wanted.begin();
    while (it != wanted.end()) {
        Poco::JSON::Array::Ptr ids = new Poco::JSON::Array();
        for (size_t i = 0; i < BRIDGE_MAX_BATCH_SIZE && it != wanted.end(); ++i, ++it) {
            ids->add(*it);
        }
        Poco::JSON::Object::Ptr in = new Poco::JSON::Object();
        in->set("$in", ids);
        Poco::JSON::Object::Ptr query = new Poco::JSON::Object();
        query->set("#userId", in);
        auto page = _connection.listContextUsers(
            contextId,
            PagingQuery{
                .skip = 0,
                .limit = static_cast<int64_t>(ids->size()),
                .sortOrder = "asc",
                .lastId = std::nullopt,
                .sortBy = std::nullopt,
                .queryAsJson = privmx::utils::Utils::stringify(query)
            }
        );
        for (const auto& userInfo : page.readItems) {
            pubKeyByUserId.emplace(userInfo.user.userId, userInfo.user.pubKey);
        }
    }

    auto resolve = [&](const std::vector<std::string>& ids) {
        std::vector<UserWithPubKey> resolved;
        resolved.reserve(ids.size());
        for (const auto& userId : ids) {
            auto found = pubKeyByUserId.find(userId);
            if (found == pubKeyByUserId.end()) {
                throw UnresolvedContainerMemberException("userId=" + userId);
            }
            resolved.push_back(UserWithPubKey{.userId = userId, .pubKey = found->second});
        }
        return resolved;
    };
    return {.users = resolve(userIds), .managers = resolve(managerIds)};
}

void ModuleBaseApi::runAutoRekey(const std::string& moduleId, const std::function<void()>& rotate) {
    try {
        rotate();
    } catch (const privmx::utils::PrivmxException& e) {
        auto code = ExceptionConverter::convert(e).getCode();
        if (code == privmx::endpoint::server::ContainerRotatedAlreadyException().getCode()) {
            invalidateModuleKeysInCache(moduleId);
            return;
        } else if (code == privmx::endpoint::server::AccessDeniedException().getCode()) {
            throw StaleKeyRekeyRequiredException("automatic re-key of moduleId=" + moduleId + " was denied");
        }
        ExceptionConverter::rethrowAsCoreException(e);
        throw Exception("ExceptionConverter rethrow error");
    }
}

ContainerCreateContext ModuleBaseApi::prepareContainerCreate(
    const std::string& contextId,
    const std::vector<UserWithPubKey>& users,
    const std::vector<UserWithPubKey>& managers
) {
    auto key = _keyProvider->generateKey();
    std::string resourceId = EndpointUtils::generateId();
    auto dio = _connection.getImpl()->createDIO(contextId, resourceId);
    auto secret = _keyProvider->generateSecret();
    auto allUsers = EndpointUtils::uniqueListUserWithPubKey(users, managers);
    auto keyEntries = _keyProvider->prepareKeysList(
        allUsers, key, dio, {.contextId = contextId, .resourceId = resourceId}, secret
    );
    return {key, resourceId, dio, secret, keyEntries};
}

DecryptedEncKeyV2 ModuleBaseApi::findEncKeyByKeyId(
    std::unordered_map<std::string, DecryptedEncKeyV2> keys,
    const std::string& keyId
) {
    for (auto key : keys) {
        if (keyId == key.first) {
            return key.second;
        }
    }
    throw UnknownModuleEncryptionKeyException();
}

DecryptedEncKeyV2 ModuleBaseApi::getAndValidateModuleCurrentEncKey(
    ModuleKeys moduleKeys,
    const KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver
) {
    assertRekeyNotNeeded(moduleKeys);
    KeyDecryptionAndVerificationRequest keyProviderRequest;
    auto location = EncKeyLocation{.contextId = moduleKeys.contextId, .resourceId = moduleKeys.moduleResourceId};
    keyProviderRequest.addOne(moduleKeys.keys, moduleKeys.currentKeyId, location);
    keyProviderRequest.addGroupKeys(moduleKeys.groupKeys, location);
    return _keyProvider->getKeysAndVerify(keyProviderRequest, groupPrivKeyResolverOr(groupPrivKeyResolver))
        .at(location)
        .at(moduleKeys.currentKeyId);
}

void ModuleBaseApi::resolveGroupEpochs(
    const std::string& contextId,
    std::vector<GroupGrantWithKey>& grants,
    std::unordered_map<std::string, GroupEpochInfo>& groupCache
) {
    auto isComplete = [](const GroupGrantWithKey& g) { return g.groupEpoch > 0 && !g.groupPubKey.empty(); };
    std::vector<std::string> toFetch;
    for (const auto& g : grants) {
        if (isComplete(g) || groupCache.find(g.groupId) != groupCache.end())
            continue;
        if (std::find(toFetch.begin(), toFetch.end(), g.groupId) == toFetch.end())
            toFetch.push_back(g.groupId);
    }
    if (!toFetch.empty() && _groupEpochResolver) {
        auto fetched = _groupEpochResolver(contextId, toFetch);
        groupCache.insert(fetched.begin(), fetched.end());
    }
    for (auto& g : grants) {
        if (isComplete(g))
            continue;
        auto resolved = groupCache.find(g.groupId);
        if (resolved == groupCache.end()) {
            throw UnresolvedGroupGranteeException("groupId=" + g.groupId);
        }
        g.groupPubKey = resolved->second.groupPubKey;
        g.groupEpoch = resolved->second.keyVersion;
    }
}

ModuleKeys ModuleBaseApi::getModuleKeys(
    const std::string& moduleId,
    const std::optional<std::set<std::string>>& keyIds,
    const std::optional<int64_t>& minimumSchemaVersion
) {
    auto keys = _keyCache.getKeys(moduleId, keyIds, minimumSchemaVersion);
    if (!keys.has_value()) {
        return getNewModuleKeysAndUpdateCache(moduleId);
    }
    return convertContainerKeyCacheModuleKeysToModuleApiFormat(keys.value());
}

void ModuleBaseApi::setNewModuleKeysInCache(
    const std::string& moduleId,
    const ModuleKeys& newKeys,
    int64_t moduleVersion
) {
    auto keys = convertModuleKeysToContainerKeyCacheFormat(newKeys, moduleVersion);
    _keyCache.set(moduleId, keys);
}

void ModuleBaseApi::invalidateModuleKeysInCache(const std::optional<std::string>& moduleId) {
    _keyCache.clear(moduleId);
}

ModuleKeys ModuleBaseApi::getNewModuleKeysAndUpdateCache(const std::string& moduleId) {
    LOG_DEBUG("PlatformModule", "getNewModuleKeysAndUpdateCache")
    auto moduleKeys = getModuleKeysAndVersionFromServer(moduleId);
    auto keys = convertModuleKeysToContainerKeyCacheFormat(moduleKeys.first, moduleKeys.second);
    _keyCache.set(moduleId, keys);
    return moduleKeys.first;
}

ContainerKeyCache::CachedModuleKeys ModuleBaseApi::convertModuleKeysToContainerKeyCacheFormat(
    const ModuleKeys& moduleKeys,
    int64_t moduleVersion
) {
    return ContainerKeyCache::CachedModuleKeys{
        .keys = moduleKeys.keys,
        .groupKeys = moduleKeys.groupKeys,
        .staleGroups = moduleKeys.staleGroups,
        .currentKeyId = moduleKeys.currentKeyId,
        .moduleSchemaVersion = moduleKeys.moduleSchemaVersion,
        .moduleResourceId = moduleKeys.moduleResourceId,
        .contextId = moduleKeys.contextId,
        .moduleVersion = moduleVersion
    };
}

ModuleKeys ModuleBaseApi::convertContainerKeyCacheModuleKeysToModuleApiFormat(
    const ContainerKeyCache::CachedModuleKeys& moduleKeys
) {
    return ModuleKeys{
        .keys = moduleKeys.keys,
        .groupKeys = moduleKeys.groupKeys,
        .staleGroups = moduleKeys.staleGroups,
        .currentKeyId = moduleKeys.currentKeyId,
        .moduleSchemaVersion = moduleKeys.moduleSchemaVersion,
        .moduleResourceId = moduleKeys.moduleResourceId,
        .contextId = moduleKeys.contextId
    };
}

std::vector<server::GroupKeyEntrySet> ModuleBaseApi::buildGroupKeyEntries(
    const std::vector<GroupGrantWithKey>& groups,
    const EncKey& key,
    const DataIntegrityObject& dio,
    const std::string& contextId,
    const std::string& resourceId,
    const std::string& containerSecret
) {
    EncKeyEncryptorV2 encryptor;
    std::vector<server::GroupKeyEntrySet> result;
    for (const auto& g : groups) {
        auto groupPubKey = privmx::crypto::PublicKey::fromBase58DER(g.groupPubKey);
        auto keySecret = privmx::utils::Hex::from(privmx::crypto::Crypto::randomBytes(32));
        auto encData = encryptor.encrypt(
            EncKeyV2ToEncrypt{
                EncKey{.id = key.id, .key = key.key}, .dio = dio,
                .location = {.contextId = contextId, .resourceId = resourceId}, .keySecret = keySecret,
                .secretHash = privmx::crypto::Crypto::hmacSha256(containerSecret, keySecret + contextId + resourceId)
            },
            groupPubKey, _userPrivKey
        );
        result.push_back(
            server::GroupKeyEntrySet{
                .group = g.groupId, .keyId = key.id, .groupEpoch = g.groupEpoch, .data = encData.toJSON()
            }
        );
    }
    return result;
}