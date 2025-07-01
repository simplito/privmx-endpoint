/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/utils/Debug.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/CoreConstants.hpp>

#include "privmx/endpoint/kvdb/KvdbApiImpl.hpp"
#include "privmx/endpoint/kvdb/ServerTypes.hpp"
#include "privmx/endpoint/kvdb/KvdbVarSerializer.hpp"
#include "privmx/endpoint/kvdb/KvdbException.hpp"
#include "privmx/endpoint/kvdb/Mapper.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

KvdbApiImpl::KvdbApiImpl(
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
    const core::Connection& connection
) : ModuleBaseApi(userPrivKey, keyProvider, host, eventMiddleware, eventChannelManager, connection),
    _gateway(gateway),
    _userPrivKey(userPrivKey),
    _keyProvider(keyProvider),
    _host(host),
    _eventMiddleware(eventMiddleware),
    _connection(connection),
    _serverApi(ServerApi(gateway)),
    _kvdbSubscriptionHelper(core::SubscriptionHelper(
        eventChannelManager, 
        "kvdb", "entries",
        [&](){},
        [&](){}
    ))
{
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&KvdbApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2));
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(std::bind(&KvdbApiImpl::processConnectedEvent, this));
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(std::bind(&KvdbApiImpl::processDisconnectedEvent, this));
}

KvdbApiImpl::~KvdbApiImpl() {
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
}

std::string KvdbApiImpl::createKvdb(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>& managers, 
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) {
    return createKvdbEx(contextId, users, managers, publicMeta, privateMeta, KVDB_TYPE_FILTER_FLAG, policies);
}

std::string KvdbApiImpl::createKvdbEx(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>& managers, 
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta, 
    const std::string& type,
    const std::optional<core::ContainerPolicy>& policies
) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, _createKvdbEx)
    auto kvdbKey = _keyProvider->generateKey();
    std::string resourceId = core::EndpointUtils::generateId();
    auto kvdbDIO = _connection.getImpl()->createDIO(
        contextId,
        resourceId
    );
    auto kvdbSecret = _keyProvider->generateSecret();

    core::ModuleDataToEncryptV5 kvdbDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::ModuleInternalMetaV5{.secret=kvdbSecret, .resourceId=resourceId, .randomId=kvdbDIO.randomId},
        .dio = kvdbDIO
    };
    auto create_kvdb_model = utils::TypedObjectFactory::createNewObject<server::KvdbCreateModel>();
    create_kvdb_model.resourceId(resourceId);
    create_kvdb_model.contextId(contextId);
    create_kvdb_model.keyId(kvdbKey.id);
    create_kvdb_model.data(_kvdbDataEncryptorV5.encrypt(kvdbDataToEncrypt, _userPrivKey, kvdbKey.key).asVar());
    auto allUsers = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    create_kvdb_model.keys(
        _keyProvider->prepareKeysList(
            allUsers, 
            kvdbKey, 
            kvdbDIO,
            {.contextId=contextId, .resourceId=resourceId},
            kvdbSecret
        )
    );

    create_kvdb_model.users(mapUsers(users));
    create_kvdb_model.managers(mapUsers(managers));
    if (type.length() > 0) {
        create_kvdb_model.type(type);
    }
    if (policies.has_value()) {
        create_kvdb_model.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _createKvdbEx, data encrypted)
    auto result = _serverApi.kvdbCreate(create_kvdb_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, _createKvdbEx, data send)
    return result.kvdbId();
}

void KvdbApiImpl::updateKvdb(
    const std::string& kvdbId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers, 
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta, 
    const int64_t version, 
    const bool force, 
    const bool forceGenerateNewKey,
    const std::optional<core::ContainerPolicy>& policies
) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, updateKvdb)

    // get current kvdb

    auto getModel = utils::TypedObjectFactory::createNewObject<server::KvdbGetModel>();
    getModel.kvdbId(kvdbId);
    auto currentKvdb = _serverApi.kvdbGet(getModel).kvdb();
    auto currentKvdbResourceId = currentKvdb.resourceIdOpt(core::EndpointUtils::generateId());

    // extract current users info
    auto usersVec {core::EndpointUtils::listToVector<std::string>(currentKvdb.users())};
    auto managersVec {core::EndpointUtils::listToVector<std::string>(currentKvdb.managers())};
    auto oldUsersAll {core::EndpointUtils::uniqueList(usersVec, managersVec)};

    auto new_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);

    // adjust key
    std::vector<std::string> deletedUsers {core::EndpointUtils::getDifference(oldUsersAll, core::EndpointUtils::usersWithPubKeyToIds(new_users))};
    std::vector<std::string> addedUsers {core::EndpointUtils::getDifference(core::EndpointUtils::usersWithPubKeyToIds(new_users), oldUsersAll)};
    std::vector<core::UserWithPubKey> usersToAddMissingKey;
    for(auto new_user: new_users) {
        if( std::find(addedUsers.begin(), addedUsers.end(), new_user.userId) != addedUsers.end()) {
            usersToAddMissingKey.push_back(new_user);
        }
    }
    bool needNewKey = deletedUsers.size() > 0 || forceGenerateNewKey;

    auto location {getModuleEncKeyLocation(currentKvdb, currentKvdbResourceId)};
    auto currentKvdbEntry = currentKvdb.data().get(currentKvdb.data().size()-1);

    auto kvdbKeys {getAndValidateModuleKeys(currentKvdb, currentKvdbResourceId)};
    auto currentKvdbKey {findEncKeyByKeyId(kvdbKeys, currentKvdbEntry.keyId())};

    auto kvdbInternalMeta = extractAndDecryptModuleInternalMeta(currentKvdbEntry, currentKvdbKey);
    if(currentKvdbKey.dataStructureVersion != 2) {
        //force update all keys if kvdb keys is in older version
        usersToAddMissingKey = new_users;
    }
    if(!_keyProvider->verifyKeysSecret(kvdbKeys, location, kvdbInternalMeta.secret)) {
        throw KvdbEncryptionKeyValidationException();
    }
    // setting kvdb Key adding new users
    core::EncKey kvdbKey = currentKvdbKey;
    core::DataIntegrityObject updateKvdbDio = _connection.getImpl()->createDIO(currentKvdb.contextId(), currentKvdbResourceId);
    privmx::utils::List<core::server::KeyEntrySet> keys = utils::TypedObjectFactory::createNewList<core::server::KeyEntrySet>();
    if(needNewKey) {
        kvdbKey = _keyProvider->generateKey();
        keys = _keyProvider->prepareKeysList(
            new_users, 
            kvdbKey, 
            updateKvdbDio,
            location,
            kvdbInternalMeta.secret
        );
    }
    if(usersToAddMissingKey.size() > 0) {
        auto tmp = _keyProvider->prepareMissingKeysForNewUsers(
            kvdbKeys,
            usersToAddMissingKey, 
            updateKvdbDio, 
            location,
            kvdbInternalMeta.secret
        );
        for(auto t: tmp) keys.add(t);
    }
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbUpdateModel>();
    auto usersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user: users) {
        usersList.add(user.userId);
    }
    auto managersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto x: managers) {
        managersList.add(x.userId);
    }
    model.id(kvdbId);
    model.resourceId(currentKvdbResourceId);
    model.keyId(kvdbKey.id);
    model.keys(keys);
    model.users(usersList);
    model.managers(managersList);
    model.version(version);
    model.force(force);
    if (policies.has_value()) {
        model.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    core::ModuleDataToEncryptV5 kvdbDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::ModuleInternalMetaV5{.secret=kvdbInternalMeta.secret, .resourceId=currentKvdbResourceId, .randomId=updateKvdbDio.randomId},
        .dio = updateKvdbDio
    };
    model.data(_kvdbDataEncryptorV5.encrypt(kvdbDataToEncrypt, _userPrivKey, kvdbKey.key).asVar());

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, updateKvdb, data encrypted)
    _serverApi.kvdbUpdate(model);
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, updateKvdb, data send)
}

void KvdbApiImpl::deleteKvdb(const std::string& kvdbId) {
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbDeleteModel>();
    model.kvdbId(kvdbId);
    _serverApi.kvdbDelete(model);
    invalidateModuleKeysInCache(kvdbId);
}

Kvdb KvdbApiImpl::getKvdb(const std::string& kvdbId) {
    return getKvdbEx(kvdbId, KVDB_TYPE_FILTER_FLAG);
}

Kvdb KvdbApiImpl::getKvdbEx(const std::string& kvdbId, const std::string& type) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, getKvdbEx)
    Poco::JSON::Object::Ptr params = new Poco::JSON::Object();
    params->set("kvdbId", kvdbId);
    if (type.length() > 0) {
        params->set("type", type);
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb,_getKvdbEx, getting kvdb)
    auto kvdb = _serverApi.kvdbGet(params).kvdb();
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _getKvdbEx, data send)
    setNewModuleKeysInCache(kvdb.id(), kvdbToModuleKeys(kvdb));
    auto result = validateDecryptAndConvertKvdbDataToKvdb(kvdb);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _getKvdbEx, data decrypted)
    return result;
}

core::PagingList<Kvdb> KvdbApiImpl::listKvdbs(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    return listKvdbsEx(contextId, pagingQuery, KVDB_TYPE_FILTER_FLAG);
}

core::PagingList<Kvdb> KvdbApiImpl::listKvdbsEx(const std::string& contextId, const core::PagingQuery& pagingQuery, const std::string& type) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, _listKvdbsEx)
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbListModel>();
    model.contextId(contextId);
    if (type.length() > 0) {
        model.type(type);
    }
    core::ListQueryMapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _listKvdbsEx, getting kvdbList)
    auto kvdbsList = _serverApi.kvdbList(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _listKvdbsEx, data send)
    for (auto kvdb : kvdbsList.kvdbs()) {
        setNewModuleKeysInCache(kvdb.id(), kvdbToModuleKeys(kvdb));
    }
    std::vector<Kvdb> kvdbs = validateDecryptAndConvertKvdbsDataToKvdbs(kvdbsList.kvdbs());
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, _listKvdbsEx, data decrypted)
    return core::PagingList<Kvdb>({
        .totalAvailable = kvdbsList.count(),
        .readItems = kvdbs
    });
}

KvdbEntry KvdbApiImpl::getEntry(const std::string& kvdbId, const std::string& key) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, getEntry)
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbEntryGetModel>();
    model.kvdbId(kvdbId);
    model.kvdbEntryKey(key);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getEntry, getting entry)
    auto entry = _serverApi.kvdbEntryGet(model).kvdbEntry();
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getEntry, data recived);
    KvdbEntry result;
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getEntry, getting kvdb)
    result = validateDecryptAndConvertEntryDataToEntry(entry, getEntryDecryptionKeys(entry));
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, getEntry, data decrypted)
    return result;
}

bool KvdbApiImpl::hasEntry(const std::string& kvdbId, const std::string& key) {
    try {
        auto model = utils::TypedObjectFactory::createNewObject<server::KvdbEntryGetModel>();
        model.kvdbId(kvdbId);
        model.kvdbEntryKey(key);
        PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getEntry, getting entry)
        auto entry = _serverApi.kvdbEntryGet(model).kvdbEntry();
    } catch (const privmx::utils::PrivmxException& e) {
        if (core::ExceptionConverter::convert(e).getCode() == privmx::endpoint::server::KvdbEntryDoesNotExistException().getCode()) {
            return false;
        }
        e.rethrow();
    }
    return true;
}

core::PagingList<std::string> KvdbApiImpl::listEntriesKeys(const std::string& kvdbId, const core::PagingQuery& pagingQuery) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, listEntriesKeys)
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbListKeysModel>();
    model.kvdbId(kvdbId);
    core::ListQueryMapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listEntriesKeys, getting entriesList)
    auto entriesList = _serverApi.kvdbListKeys(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listEntriesKeys, data send)
    std::vector<std::string> keys;
    for(auto key : entriesList.kvdbEntryKeys()) {
        keys.push_back(key);
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, listEntriesKeys, data decrypted)
    return core::PagingList<std::string>({
        .totalAvailable = entriesList.count(),
        .readItems = keys
    });
}

core::PagingList<KvdbEntry> KvdbApiImpl::listEntries(const std::string& kvdbId, const core::PagingQuery& pagingQuery) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, listEntry)
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbListEntriesModel>();
    model.kvdbId(kvdbId);
    core::ListQueryMapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listEntry, getting listEntry)
    auto entriesList = _serverApi.kvdbListEntries(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listEntriesKeys, data send)
    auto kvdb = entriesList.kvdb();
    assertKvdbDataIntegrity(kvdb);
    setNewModuleKeysInCache(kvdb.id(), kvdbToModuleKeys(kvdb));
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listEntriesKeys, data send)
    auto entries = validateDecryptAndConvertKvdbEntriesDataToKvdbEntries(entriesList.kvdbEntries(), kvdbToModuleKeys(kvdb));
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, listEntriesKeys, data decrypted)
    return core::PagingList<KvdbEntry>({
        .totalAvailable = entriesList.count(),
        .readItems = entries
    });
}

void KvdbApiImpl::setEntry(const std::string& kvdbId, const std::string& key, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data, int64_t version) {
    try {
        return setEntryRequest(kvdbId, key, publicMeta, privateMeta, data, version, getModuleKeys(kvdbId));
    } catch (const privmx::utils::PrivmxException& e) {
        if (core::ExceptionConverter::convert(e).getCode() == privmx::endpoint::server::InvalidKeyIdException().getCode()) {
            //get new kvdb key to cache 
            return setEntryRequest(kvdbId, key, publicMeta, privateMeta, data, version, getNewModuleKeysAndUpdateCache(kvdbId));
        }
        e.rethrow();
    }
}
    
void KvdbApiImpl::setEntryRequest(
    const std::string& kvdbId, 
    const std::string& key, 
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta, 
    const core::Buffer& data, 
    int64_t version,
    const core::ModuleBaseApi::ModuleKeys& keys
) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, sendEntry);
    auto msgKey = getAndValidateModuleCurrentEncKey(keys);
    auto  send_entry_model = utils::TypedObjectFactory::createNewObject<server::KvdbEntrySetModel>();
    send_entry_model.kvdbId(kvdbId);
    send_entry_model.kvdbEntryKey(key);
    send_entry_model.version(version);
    send_entry_model.keyId(msgKey.id);
    send_entry_model.kvdbEntryValue(encryptEntryData(kvdbId, key, publicMeta, privateMeta, data, keys));
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, sendEntry, data encrypted)
    _serverApi.kvdbEntrySet(send_entry_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, sendEntry, data send)
}

void KvdbApiImpl::deleteEntry(const std::string& kvdbId, const std::string& key) {
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbEntryDeleteModel>();
    model.kvdbId(kvdbId);
    model.kvdbEntryKey(key);
    _serverApi.kvdbEntryDelete(model);
}

std::map<std::string, bool> KvdbApiImpl::deleteEntries(const std::string& kvdbId, const std::vector<std::string>& keys) {
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbEntryDeleteManyModel>();
    model.kvdbId(kvdbId);
    model.kvdbEntryKeys(utils::TypedObjectFactory::createNewList<std::string>());
    for(auto key : keys) {
        model.kvdbEntryKeys().add(key);
    }
    auto deleteStatuses = _serverApi.kvdbEntryDeleteMany(model).results();
    std::map<std::string, bool> result;
    for(auto deleteStatus : deleteStatuses) {
        result.insert(std::make_pair(deleteStatus.kvdbEntryKey(), deleteStatus.status() == "OK"));
    }
    return result;
}

void KvdbApiImpl::processNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    if(notification.source == core::EventSource::INTERNAL) {
        _kvdbSubscriptionHelper.processSubscriptionNotificationEvent(type,notification);
        return;
    }
    if(!_kvdbSubscriptionHelper.hasSubscription(notification.subscriptions)) {
        return;
    }
    if (type == "kvdbCreated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbInfo>(notification.data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            setNewModuleKeysInCache(raw.id(), kvdbToModuleKeys(raw));
            privmx::endpoint::kvdb::Kvdb data = validateDecryptAndConvertKvdbDataToKvdb(raw); 
            std::shared_ptr<KvdbCreatedEvent> event(new KvdbCreatedEvent());
            event->channel = "kvdb";
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbUpdated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbInfo>(notification.data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            setNewModuleKeysInCache(raw.id(), kvdbToModuleKeys(raw));
            privmx::endpoint::kvdb::Kvdb data = validateDecryptAndConvertKvdbDataToKvdb(raw); 
            std::shared_ptr<KvdbUpdatedEvent> event(new KvdbUpdatedEvent());
            event->channel = "kvdb";
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbDeleted") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbDeletedEventData>(notification.data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            invalidateModuleKeysInCache(raw.kvdbId());
            auto data = Mapper::mapToKvdbDeletedEventData(raw);
            std::shared_ptr<KvdbDeletedEvent> event(new KvdbDeletedEvent());
            event->channel = "kvdb";
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbStats") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbStatsEventData>(notification.data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            auto data = Mapper::mapToKvdbStatsEventData(raw);
            std::shared_ptr<KvdbStatsChangedEvent> event(new KvdbStatsChangedEvent());
            event->channel = "kvdb";
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbNewEntry") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbEntryInfo>(notification.data);
        auto data = validateDecryptAndConvertEntryDataToEntry(raw, getEntryDecryptionKeys(raw));
        std::shared_ptr<KvdbNewEntryEvent> event(new KvdbNewEntryEvent());
        event->channel = "kvdb/" + raw.kvdbId() + "/entries";
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "kvdbUpdatedEntry") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbEntryInfo>(notification.data);
        auto data = validateDecryptAndConvertEntryDataToEntry(raw, getEntryDecryptionKeys(raw));
        std::shared_ptr<KvdbEntryUpdatedEvent> event(new KvdbEntryUpdatedEvent());
        event->channel = "kvdb/" + raw.kvdbId() + "/entries";
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "kvdbDeletedEntry") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbDeletedEntryEventData>(notification.data);
        auto data = Mapper::mapToKvdbDeletedEntryEventData(raw);
        std::shared_ptr<KvdbEntryDeletedEvent> event(new KvdbEntryDeletedEvent());
        event->channel = "kvdb/" + raw.kvdbId() + "/entries";
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    }
}

void KvdbApiImpl::subscribeForKvdbEvents() {
    if(_kvdbSubscriptionHelper.hasSubscriptionForModule()) {
        throw AlreadySubscribedException();
    }
    _kvdbSubscriptionHelper.subscribeForModule();
}

void KvdbApiImpl::unsubscribeFromKvdbEvents() {
    if(!_kvdbSubscriptionHelper.hasSubscriptionForModule()) {
        throw NotSubscribedException();
    }
    _kvdbSubscriptionHelper.unsubscribeFromModule();
}

void KvdbApiImpl::subscribeForEntryEvents(std::string kvdbId) {
    assertKvdbExist(kvdbId);
    if(_kvdbSubscriptionHelper.hasSubscriptionForModuleEntry(kvdbId)) {
        throw AlreadySubscribedException(kvdbId);
    }
    _kvdbSubscriptionHelper.subscribeForModuleEntry(kvdbId);
}

void KvdbApiImpl::unsubscribeFromEntryEvents(std::string kvdbId) {
    assertKvdbExist(kvdbId);
    if(!_kvdbSubscriptionHelper.hasSubscriptionForModuleEntry(kvdbId)) {
        throw NotSubscribedException(kvdbId);
    }
    _kvdbSubscriptionHelper.unsubscribeFromModuleEntry(kvdbId);
}

void KvdbApiImpl::processConnectedEvent() {
}

void KvdbApiImpl::processDisconnectedEvent() {
}

privmx::utils::List<std::string> KvdbApiImpl::mapUsers(const std::vector<core::UserWithPubKey>& users) {
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user : users) {
        result.add(user.userId);
    }
    return result;
}

Kvdb KvdbApiImpl::convertServerKvdbToLibKvdb(
    server::KvdbInfo kvdb,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t& statusCode,
    const int64_t& schemaVersion
) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    if(!kvdb.usersEmpty()) {
        for (auto x : kvdb.users()) {
            users.push_back(x);
        }
    }
    if(!kvdb.managersEmpty()) {
        for (auto x : kvdb.managers()) {
            managers.push_back(x);
        }
    }

    return Kvdb{
        .contextId = kvdb.contextIdOpt(std::string()),
        .kvdbId = kvdb.idOpt(std::string()),
        .createDate = kvdb.createDateOpt(0),
        .creator = kvdb.creatorOpt(std::string()),
        .lastModificationDate = kvdb.lastModificationDateOpt(0),
        .lastModifier = kvdb.lastModifierOpt(std::string()),
        .users = users,
        .managers = managers,
        .version = kvdb.versionOpt(0),
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .entries = kvdb.entriesOpt(0),
        .lastEntryDate = kvdb.lastEntryDateOpt(0),
        .policy = core::Factory::parsePolicyServerObject(kvdb.policyOpt(Poco::JSON::Object::Ptr(new Poco::JSON::Object))),
        .statusCode = statusCode,
        .schemaVersion = schemaVersion
    };
}

Kvdb KvdbApiImpl::convertDecryptedKvdbDataV5ToKvdb(server::KvdbInfo kvdbInfo, const core::DecryptedModuleDataV5& kvdbData) {
    return convertServerKvdbToLibKvdb(
        kvdbInfo,
        kvdbData.publicMeta,
        kvdbData.privateMeta,
        kvdbData.statusCode,
        KvdbDataSchema::Version::VERSION_5
    );
}

KvdbDataSchema::Version KvdbApiImpl::getKvdbDataEntryStructureVersion(server::KvdbDataEntry kvdbEntry) {
    if (kvdbEntry.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(kvdbEntry.data());
        auto version = versioned.versionOpt(core::ModuleDataSchema::Version::UNKNOWN);
        switch (version) {
            case core::ModuleDataSchema::Version::VERSION_5:
                return KvdbDataSchema::Version::VERSION_5;
            default:
                return KvdbDataSchema::Version::UNKNOWN;
        }
    }
    return KvdbDataSchema::Version::UNKNOWN;
}

std::tuple<Kvdb, core::DataIntegrityObject> KvdbApiImpl::decryptAndConvertKvdbDataToKvdb(server::KvdbInfo kvdb, server::KvdbDataEntry kvdbEntry, const core::DecryptedEncKey& encKey) {
    switch (getKvdbDataEntryStructureVersion(kvdbEntry)) {
        case KvdbDataSchema::Version::UNKNOWN: {
            auto e = UnknownKvdbFormatException();
            return std::make_tuple(convertServerKvdbToLibKvdb(kvdb,{},{},e.getCode()), core::DataIntegrityObject());
        }
        case KvdbDataSchema::Version::VERSION_5: {
            auto decryptedKvdbData = decryptModuleDataV5(kvdbEntry, encKey);
            return std::make_tuple(convertDecryptedKvdbDataV5ToKvdb(kvdb, decryptedKvdbData), decryptedKvdbData.dio);
        }
    }    
    auto e = UnknownKvdbFormatException();
    return std::make_tuple(convertServerKvdbToLibKvdb(kvdb,{},{},e.getCode()), core::DataIntegrityObject());
}

std::vector<Kvdb> KvdbApiImpl::validateDecryptAndConvertKvdbsDataToKvdbs(privmx::utils::List<server::KvdbInfo> kvdbs) {
    // Create Result Array
    std::vector<Kvdb> result(kvdbs.size());
    // Validate data Integrity
    for (size_t i = 0; i < kvdbs.size(); i++) {
        auto kvdb = kvdbs.get(i);
        result[i].statusCode = validateKvdbDataIntegrity(kvdb);
        if(result[i].statusCode != 0) {
            result[i] = convertServerKvdbToLibKvdb(kvdb, {}, {}, result[i].statusCode);
        }
    }
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    // Create request to KeyProvider for keys
    for (size_t i = 0; i < kvdbs.size(); i++) {
        auto kvdb = kvdbs.get(i);
        core::EncKeyLocation location{.contextId=kvdb.contextId(), .resourceId=kvdb.resourceIdOpt("")};
        auto kvdb_data_entry = kvdb.data().get(kvdb.data().size()-1);
        keyProviderRequest.addOne(kvdb.keys(), kvdb_data_entry.keyId(), location);
    }
    // Send request to KeyProvider
    auto kvdbsKeys {_keyProvider->getKeysAndVerify(keyProviderRequest)};
    std::vector<core::DataIntegrityObject> kvdbsDIO(kvdbs.size());
    std::map<std::string, bool> duplication_check;
    for (size_t i = 0; i < kvdbs.size(); i++) {
        if(result[i].statusCode != 0) {
            kvdbsDIO.push_back(core::DataIntegrityObject{});
        } else {
            auto kvdb = kvdbs.get(i);
            try {
                auto tmp = decryptAndConvertKvdbDataToKvdb(
                    kvdb, 
                    kvdb.data().get(kvdb.data().size()-1), 
                    kvdbsKeys.at(core::EncKeyLocation{.contextId=kvdb.contextId(), .resourceId=kvdb.resourceIdOpt("")}).at(kvdb.data().get(kvdb.data().size()-1).keyId())
                );
                result[i] = std::get<0>(tmp);
                auto kvdbDIO = std::get<1>(tmp);
                kvdbsDIO[i] = kvdbDIO;
                //find duplication
                std::string fullRandomId = kvdbDIO.randomId + "-" + std::to_string(kvdbDIO.timestamp);
                if(duplication_check.find(fullRandomId) == duplication_check.end()) {
                    duplication_check.insert(std::make_pair(fullRandomId, true));
                } else {
                    result[i].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
                }
            } catch (const core::Exception& e) {
                result[i] = convertServerKvdbToLibKvdb(kvdb, {}, {}, e.getCode());
                kvdbsDIO[i] = core::DataIntegrityObject{};
            }
        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (size_t i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            verifierInput.push_back(core::VerificationRequest{
                .contextId = result[i].contextId,
                .senderId = result[i].lastModifier,
                .senderPubKey = kvdbsDIO[i].creatorPubKey,
                .date = result[i].lastModificationDate,
                .bridgeIdentity = kvdbsDIO[i].bridgeIdentity
            });
        }
    }
    std::vector<bool> verified;
    verified =_connection.getImpl()->getUserVerifier()->verify(verifierInput);
    for (size_t j = 0, i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            result[i].statusCode = verified[j] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
            j++;
        }
    }
    return result;
}

Kvdb KvdbApiImpl::validateDecryptAndConvertKvdbDataToKvdb(server::KvdbInfo kvdb) {
// Validate data Integrity
    auto statusCode = validateKvdbDataIntegrity(kvdb);
    if(statusCode != 0) {
        return convertServerKvdbToLibKvdb(kvdb, {}, {}, statusCode);
    }
    // Get current KvdbEntry and Key
    auto kvdb_data_entry = kvdb.data().get(kvdb.data().size()-1);
    // Create request to KeyProvider for keys
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=kvdb.contextId(), .resourceId=kvdb.resourceIdOpt("")};
    keyProviderRequest.addOne(kvdb.keys(), kvdb_data_entry.keyId(), location);
    //Send request to KeyProvider
    auto key = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(kvdb_data_entry.keyId());
    Kvdb result;
    core::DataIntegrityObject kvdbDIO;
    // Decrypt
    std::tie(result, kvdbDIO) = decryptAndConvertKvdbDataToKvdb(kvdb, kvdb_data_entry, key);
    // Validate with UserVerifier
    if(result.statusCode != 0) return result;
    std::vector<core::VerificationRequest> verifierInput {};
    verifierInput.push_back(core::VerificationRequest{
        .contextId = result.contextId,
        .senderId = result.lastModifier,
        .senderPubKey = kvdbDIO.creatorPubKey,
        .date = result.lastModificationDate,
        .bridgeIdentity = kvdbDIO.bridgeIdentity
    });
    std::vector<bool> verified;
    verified =_connection.getImpl()->getUserVerifier()->verify(verifierInput);
    result.statusCode = verified[0] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    return result;    
}


DecryptedKvdbEntryDataV5 KvdbApiImpl::decryptKvdbEntryDataV5(server::KvdbEntryInfo entry, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedEntryData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedKvdbEntryDataV5>(entry.kvdbEntryValue());
        if(encKey.statusCode != 0) {
            auto tmp = _entryDataEncryptorV5.extractPublic(encryptedEntryData);
            tmp.statusCode = encKey.statusCode;
            return tmp;
        }
        return _entryDataEncryptorV5.decrypt(encryptedEntryData, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedKvdbEntryDataV5{{.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_5, .statusCode = e.getCode()}, {},{},{},{},{},{}};
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedKvdbEntryDataV5{{.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_5, .statusCode = core::ExceptionConverter::convert(e).getCode()}, {},{},{},{},{},{}};
    } catch (...) {
        return DecryptedKvdbEntryDataV5{{.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_5, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE}, {},{},{},{},{},{}};
    }
}

KvdbEntry KvdbApiImpl::convertServerKvdbEntryToLibKvdbEntry(
    server::KvdbEntryInfo entry,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    const std::string& authorPubKey,
    const int64_t& statusCode,
    const int64_t& schemaVersion
) {
    return KvdbEntry{
        .info = {
            .kvdbId = entry.kvdbIdOpt(std::string()),
            .key = entry.kvdbEntryKeyOpt(std::string()),
            .createDate = entry.createDateOpt(0),
            .author = entry.authorOpt(std::string()),
        },
        .publicMeta = publicMeta, 
        .privateMeta = privateMeta,
        .data = data,
        .authorPubKey = authorPubKey,
        .version = entry.versionOpt(0),
        .statusCode = statusCode,
        .schemaVersion = schemaVersion
    };
}

KvdbEntry KvdbApiImpl::convertDecryptedKvdbEntryDataV5ToKvdbEntry(server::KvdbEntryInfo entry, DecryptedKvdbEntryDataV5 entryData) {
    return convertServerKvdbEntryToLibKvdbEntry(
        entry,
        entryData.publicMeta, 
        entryData.privateMeta,
        entryData.data,
        entryData.authorPubKey,
        entryData.statusCode,
        KvdbEntryDataSchema::Version::VERSION_5
    );
}


KvdbEntryDataSchema::Version KvdbApiImpl::getEntryDataStructureVersion(server::KvdbEntryInfo entry) {
    if (entry.kvdbEntryValue().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(entry.kvdbEntryValue());
        auto version = versioned.versionOpt(core::ModuleDataSchema::Version::UNKNOWN);
        switch (version) {
            case core::ModuleDataSchema::Version::VERSION_5:
                return KvdbEntryDataSchema::Version::VERSION_5;
            default:
                return KvdbEntryDataSchema::Version::UNKNOWN;
        }
    }
    return KvdbEntryDataSchema::Version::UNKNOWN;
}

std::tuple<KvdbEntry, core::DataIntegrityObject> KvdbApiImpl::decryptAndConvertEntryDataToEntry(server::KvdbEntryInfo entry, const core::DecryptedEncKey& encKey) {
    switch (getEntryDataStructureVersion(entry)) {
        case KvdbEntryDataSchema::Version::UNKNOWN: {
            auto e = UnknownKvdbEntryFormatException();
            return std::make_tuple(convertServerKvdbEntryToLibKvdbEntry(entry,{},{},{},{},e.getCode()), core::DataIntegrityObject());
        }
        case KvdbEntryDataSchema::Version::VERSION_5: {
            auto decryptEntry = decryptKvdbEntryDataV5(entry, encKey);
            return std::make_tuple(convertDecryptedKvdbEntryDataV5ToKvdbEntry(entry, decryptEntry), decryptEntry.dio);
        }
    }
    auto e = UnknownKvdbEntryFormatException();
    return std::make_tuple(convertServerKvdbEntryToLibKvdbEntry(entry,{},{},{},{},e.getCode()), core::DataIntegrityObject());
}

std::vector<KvdbEntry> KvdbApiImpl::validateDecryptAndConvertKvdbEntriesDataToKvdbEntries(utils::List<server::KvdbEntryInfo> entries, const core::ModuleBaseApi::ModuleKeys& kvdbKeys) {
   std::set<std::string> keyIds;
    for (auto entry : entries) {
        keyIds.insert(entry.keyId());
    }
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=kvdbKeys.contextId, .resourceId=kvdbKeys.moduleResourceId};
    keyProviderRequest.addMany(kvdbKeys.keys, keyIds, location);
    auto keyMap = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location);
    std::vector<KvdbEntry> result;
    std::vector<core::DataIntegrityObject> entriesDIO;
    std::map<std::string, bool> duplication_check;
    for (auto entry : entries) {
        try {
            auto statusCode = validateEntryDataIntegrity(entry, kvdbKeys.moduleResourceId);
            if(statusCode == 0) {
                auto tmp = decryptAndConvertEntryDataToEntry(entry, keyMap.at(entry.keyId()));
                result.push_back(std::get<0>(tmp));
                auto entryDIO = std::get<1>(tmp);
                entriesDIO.push_back(entryDIO);
                //find duplication
                std::string fullRandomId = entryDIO.randomId + "-" + std::to_string(entryDIO.timestamp);
                if(duplication_check.find(fullRandomId) == duplication_check.end()) {
                    duplication_check.insert(std::make_pair(fullRandomId, true));
                } else {
                    result[result.size()-1].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
                }
            } else {
                result.push_back(convertServerKvdbEntryToLibKvdbEntry(entry,{},{},{},{},statusCode));
            }
        } catch (const core::Exception& e) {
            result.push_back(convertServerKvdbEntryToLibKvdbEntry(entry,{},{},{},{},e.getCode()));
        } catch (const privmx::utils::PrivmxException& e) {
            result.push_back(convertServerKvdbEntryToLibKvdbEntry(entry,{},{},{},{},core::ExceptionConverter::convert(e).getCode()));
        } catch (...) {
            result.push_back(convertServerKvdbEntryToLibKvdbEntry(entry,{},{},{},{},ENDPOINT_CORE_EXCEPTION_CODE));
        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (size_t i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            verifierInput.push_back(core::VerificationRequest{
                .contextId = kvdbKeys.contextId,
                .senderId = result[i].info.author,
                .senderPubKey = result[i].authorPubKey,
                .date = result[i].info.createDate,
                .bridgeIdentity = entriesDIO[i].bridgeIdentity
            });
        }
    }
    std::vector<bool> verified;
    verified = _connection.getImpl()->getUserVerifier()->verify(verifierInput);
    for (size_t j = 0, i = 0; i < result.size(); ++i) {
        if (result[i].statusCode == 0) {
            result[i].statusCode = verified[j] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
            j++;
        }
    }
    return result;
}

KvdbEntry KvdbApiImpl::validateDecryptAndConvertEntryDataToEntry(server::KvdbEntryInfo entry, const core::ModuleBaseApi::ModuleKeys& kvdbKeys) {
    try {
        auto keyId = entry.keyId();
        // Validate data Integrity
        auto statusCode = validateEntryDataIntegrity(entry, kvdbKeys.moduleResourceId);
        if(statusCode != 0) {
            return convertServerKvdbEntryToLibKvdbEntry(entry, {}, {}, {}, {}, statusCode);
        }
        // Create request to KeyProvider for keys
        core::KeyDecryptionAndVerificationRequest keyProviderRequest;
        core::EncKeyLocation location{.contextId=entry.contextId(), .resourceId=kvdbKeys.moduleResourceId};
        keyProviderRequest.addOne(kvdbKeys.keys, keyId, location);
        // Send request to KeyProvider
        auto encKey = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(keyId);
        // decrypt entry
        KvdbEntry result;
        core::DataIntegrityObject entryDIO;
        std::tie(result, entryDIO) = decryptAndConvertEntryDataToEntry(entry, encKey);
        if(result.statusCode != 0) return result;
        // Validate with UserVerifier
        std::vector<core::VerificationRequest> verifierInput {};
            verifierInput.push_back(core::VerificationRequest{
                .contextId = entry.contextId(),
                .senderId = result.info.author,
                .senderPubKey = result.authorPubKey,
                .date = result.info.createDate,
                .bridgeIdentity = entryDIO.bridgeIdentity
            });
        std::vector<bool> verified;
        verified = _connection.getImpl()->getUserVerifier()->verify(verifierInput);
        result.statusCode = verified[0] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
        return result;
    } catch (const core::Exception& e) {
        return convertServerKvdbEntryToLibKvdbEntry(entry,{},{},{},{},e.getCode());
    } catch (const privmx::utils::PrivmxException& e) {
        return convertServerKvdbEntryToLibKvdbEntry(entry,{},{},{},{},core::ExceptionConverter::convert(e).getCode());
    } catch (...) {
        return convertServerKvdbEntryToLibKvdbEntry(entry,{},{},{},{},ENDPOINT_CORE_EXCEPTION_CODE);
    }
}

core::ModuleBaseApi::ModuleKeys KvdbApiImpl::getEntryDecryptionKeys(server::KvdbEntryInfo entry, std::optional<server::KvdbInfo> kvdb) {
    auto keyId = entry.keyId();
    if(kvdb.has_value()) {
        return kvdbToModuleKeys(kvdb.value());
    } else {
        // get decryption Key form cache
        kvdb::KvdbDataSchema::Version minimumKvdbSchemaVersion;
        switch (getEntryDataStructureVersion(entry)) {
            case kvdb::KvdbEntryDataSchema::Version::UNKNOWN:
                minimumKvdbSchemaVersion = kvdb::KvdbDataSchema::UNKNOWN;
                break;
            case kvdb::KvdbEntryDataSchema::Version::VERSION_5:
                minimumKvdbSchemaVersion = kvdb::KvdbDataSchema::VERSION_5;
                break;
        }
        return getModuleKeys(entry.kvdbId(), std::set<std::string>{keyId}, minimumKvdbSchemaVersion);
    }
}

Poco::Dynamic::Var KvdbApiImpl::encryptEntryData(
    const std::string& kvdbId, 
    const std::string& resourceId, 
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta, 
    const core::Buffer& data, 
    const core::ModuleBaseApi::ModuleKeys& kvdbKeys
) {
    core::DecryptedEncKeyV2 msgKey = getAndValidateModuleCurrentEncKey(kvdbKeys);
    switch (msgKey.dataStructureVersion) {
        case core::EncryptionKeyDataSchema::Version::UNKNOWN: 
            case core::EncryptionKeyDataSchema::Version::VERSION_1: 
            throw UnknownKvdbFormatException();
        case core::EncryptionKeyDataSchema::Version::VERSION_2:  {
            auto entryDIO = _connection.getImpl()->createDIO(
                kvdbKeys.contextId,
                resourceId,
                kvdbId,
                kvdbKeys.moduleResourceId
            );
            KvdbEntryDataToEncryptV5 entryData {
                .publicMeta = publicMeta,
                .privateMeta = privateMeta,
                .data = data,
                .internalMeta = std::nullopt,
                .dio = entryDIO
            };
            auto encryptedEntryData = _entryDataEncryptorV5.encrypt(entryData, _userPrivKey, msgKey.key);
            return encryptedEntryData.asVar();
        }
    }
    throw UnknownKvdbFormatException();
}

void KvdbApiImpl::assertKvdbExist(const std::string& kvdbId) {
    auto params = privmx::utils::TypedObjectFactory::createNewObject<kvdb::server::KvdbGetModel>();
    params.kvdbId(kvdbId);
    _serverApi.kvdbGet(params);
}

core::ModuleBaseApi::ModuleKeys KvdbApiImpl::getModuleKeysFormServer(std::string moduleId) {
    auto params = privmx::utils::TypedObjectFactory::createNewObject<kvdb::server::KvdbGetModel>();
    params.kvdbId(moduleId);
    auto kvdb = _serverApi.kvdbGet(params).kvdb();
    // validate kvdb Data before returning data
    assertKvdbDataIntegrity(kvdb);
    return kvdbToModuleKeys(kvdb);
}

core::ModuleBaseApi::ModuleKeys KvdbApiImpl::kvdbToModuleKeys(server::KvdbInfo kvdb) {
    return core::ModuleBaseApi::ModuleKeys{
        .keys=kvdb.keys(),
        .currentKeyId=kvdb.keyId(),
        .moduleSchemaVersion=getKvdbDataEntryStructureVersion(kvdb.data().get(kvdb.data().size()-1)),
        .moduleResourceId=kvdb.resourceIdOpt(""),
        .contextId = kvdb.contextId()
    };
}

void KvdbApiImpl::assertKvdbDataIntegrity(server::KvdbInfo kvdb) {
    auto kvdb_data_entry = kvdb.data().get(kvdb.data().size()-1);
    switch (getKvdbDataEntryStructureVersion(kvdb_data_entry)) {
        case KvdbDataSchema::Version::UNKNOWN:
            throw UnknownKvdbFormatException();
        case KvdbDataSchema::Version::VERSION_5: {
            auto kvdb_data = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::EncryptedModuleDataV5>(kvdb_data_entry.data());
            auto dio = _kvdbDataEncryptorV5.getDIOAndAssertIntegrity(kvdb_data);
            if(
                dio.contextId != kvdb.contextId() ||
                dio.resourceId != kvdb.resourceIdOpt("") ||
                dio.creatorUserId != kvdb.lastModifier() ||
                !core::TimestampValidator::validate(dio.timestamp, kvdb.lastModificationDate())
            ) {
                throw KvdbDataIntegrityException();
            }
            return;
        }
    }
    throw UnknownKvdbFormatException();
}

uint32_t KvdbApiImpl::validateKvdbDataIntegrity(server::KvdbInfo kvdb) {
    try {
        assertKvdbDataIntegrity(kvdb);
        return 0;
    } catch (const core::Exception& e) {
        return e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        return e.getCode();
    } catch (...) {
        return ENDPOINT_CORE_EXCEPTION_CODE;
    } 
    return UnknownKvdbFormatException().getCode();
}

uint32_t KvdbApiImpl::validateEntryDataIntegrity(server::KvdbEntryInfo entry, const std::string& kvdbResourceId) {
    try {
        switch (getEntryDataStructureVersion(entry)) {
            case KvdbEntryDataSchema::Version::UNKNOWN:
                return UnknownKvdbEntryFormatException().getCode();
            case KvdbEntryDataSchema::Version::VERSION_5: {
                auto encData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedKvdbEntryDataV5>(entry.kvdbEntryValue());
                auto dio = _entryDataEncryptorV5.getDIOAndAssertIntegrity(encData);
                if(
                    dio.contextId != entry.contextId() ||
                    dio.resourceId != entry.kvdbEntryKey() ||
                    !dio.containerId.has_value() || dio.containerId.value() != entry.kvdbId() ||
                    !dio.containerResourceId.has_value() || dio.containerResourceId.value() != kvdbResourceId ||
                    dio.creatorUserId != entry.lastModifier() ||
                    !core::TimestampValidator::validate(dio.timestamp, entry.lastModificationDate())
                ) {
                    return KvdbEntryDataIntegrityException().getCode();
                }
                return 0;
            }
        }
    } catch (const core::Exception& e) {
    return e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        return e.getCode();
    } catch (...) {
        return ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return UnknownKvdbEntryFormatException().getCode();
}


