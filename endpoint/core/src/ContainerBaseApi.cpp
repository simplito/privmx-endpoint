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
#include <privmx/utils/Utils.hpp>
#include <set>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/crypto/PublicKeyCache.hpp>

#include "privmx/endpoint/core/ContainerBaseApi.hpp"
#include "privmx/endpoint/core/encryptors/EncKey/EncKeyEncryptorV2.hpp"
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/Types.hpp>

using namespace privmx::endpoint::core;

ContainerBaseApi::ContainerBaseApi(
    const core::PrivateKey& userPrivKey,
    const std::shared_ptr<KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<EventMiddleware>& eventMiddleware,
    const Connection& connection
)
    : _guardedExecutor(std::make_shared<privmx::utils::GuardedExecutor>()), _userPrivKey(userPrivKey),
      _keyProvider(keyProvider), _host(host), _eventMiddleware(eventMiddleware), _connection(connection) {}

void ContainerBaseApi::initGroupPrivKeyResolver(const KeyProvider::GroupPrivKeyResolver& resolver) {
    _groupPrivKeyResolver = resolver;
}

ContainerBaseApi::ContainerRoster ContainerBaseApi::resolveRosterPubKeys(
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

ContainerCreateContext ContainerBaseApi::prepareContainerCreate(
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

std::vector<server::KeyEntrySet> ContainerBaseApi::buildRosterKeyEntries(const ContainerUpdatePlan& plan) {
    std::vector<server::KeyEntrySet> keyEntries;
    if (plan.needNewKey) {
        keyEntries = _keyProvider->prepareKeysList(
            plan.roster->getNewUsers(), plan.ctx.key, plan.ctx.dio, plan.ctx.location, plan.ctx.secret
        );
    }
    auto usersToAddMissingKey{plan.roster->getUsersToAddKey()};
    if (!usersToAddMissingKey.empty()) {
        auto tmp = _keyProvider->prepareMissingKeysForNewUsers(
            plan.containerKeys, usersToAddMissingKey, plan.ctx.dio, plan.ctx.location, plan.ctx.secret
        );
        keyEntries.insert(keyEntries.end(), tmp.begin(), tmp.end());
    }
    return keyEntries;
}

void ContainerBaseApi::assertRekeyNotNeeded(const server::ContainerInfoBase& container) {
    assertNoStaleGroups(container.staleGroups);
}

void ContainerBaseApi::assertRekeyNotNeeded(const ModuleKeys& moduleKeys) {
    assertNoStaleGroups(moduleKeys.staleGroups);
}

void ContainerBaseApi::assertNoStaleGroups(const std::vector<std::string>& staleGroups) {
    if (staleGroups.empty()) {
        return;
    }
    std::string names;
    for (const auto& groupId : staleGroups) {
        names += names.empty() ? groupId : "," + groupId;
    }
    throw StaleKeyRekeyRequiredException("staleGroups=" + names);
}

DecryptedEncKeyV2 ContainerBaseApi::findEncKeyByKeyId(
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

DecryptedEncKeyV2 ContainerBaseApi::getAndValidateModuleCurrentEncKey(ModuleKeys moduleKeys) {
    assertRekeyNotNeeded(moduleKeys);
    KeyDecryptionAndVerificationRequest keyProviderRequest;
    auto location = EncKeyLocation{.contextId = moduleKeys.contextId, .resourceId = moduleKeys.moduleResourceId};
    keyProviderRequest.addOne(moduleKeys.keys, moduleKeys.currentKeyId, location);
    keyProviderRequest.addGroupKeys(moduleKeys.groupKeys, location);
    return _keyProvider->getKeysAndVerify(keyProviderRequest, _groupPrivKeyResolver)
        .at(location)
        .at(moduleKeys.currentKeyId);
}

ModuleKeys ContainerBaseApi::getModuleKeys(
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

void ContainerBaseApi::setNewModuleKeysInCache(
    const std::string& moduleId,
    const ModuleKeys& newKeys,
    int64_t moduleVersion
) {
    auto keys = convertModuleKeysToContainerKeyCacheFormat(newKeys, moduleVersion);
    _keyCache.set(moduleId, keys);
}

void ContainerBaseApi::invalidateModuleKeysInCache(const std::optional<std::string>& moduleId) {
    _keyCache.clear(moduleId);
}

ModuleKeys ContainerBaseApi::getNewModuleKeysAndUpdateCache(const std::string& moduleId) {
    LOG_DEBUG("PlatformModule", "getNewModuleKeysAndUpdateCache")
    auto moduleKeys = getModuleKeysAndVersionFromServer(moduleId);
    auto keys = convertModuleKeysToContainerKeyCacheFormat(moduleKeys.first, moduleKeys.second);
    _keyCache.set(moduleId, keys);
    return moduleKeys.first;
}

ContainerKeyCache::CachedModuleKeys ContainerBaseApi::convertModuleKeysToContainerKeyCacheFormat(
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

ModuleKeys ContainerBaseApi::convertContainerKeyCacheModuleKeysToModuleApiFormat(
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

std::vector<server::GroupKeyEntrySet> ContainerBaseApi::buildGroupKeyEntries(
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
        auto groupPubKey = core::PublicKeyCache::getInstance()->fromBase58DER(g.groupPubKey);
        auto keySecret = privmx::utils::Hex::from(privmx::crypto::Crypto::randomBytes(32));
        auto encData = encryptor.encrypt(
            EncKeyV2ToEncrypt{
                EncKey{.id = key.id, .key = key.key}, dio,
                EncKeyLocation{.contextId = contextId, .resourceId = resourceId}, keySecret,
                privmx::crypto::Crypto::hmacSha256(containerSecret, keySecret + contextId + resourceId)
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
