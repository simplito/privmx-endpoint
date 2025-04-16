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

#include "privmx/endpoint/kvdb/KvdbApiImpl.hpp"
#include "privmx/endpoint/kvdb/ServerTypes.hpp"
#include "privmx/endpoint/kvdb/KvdbVarSerializer.hpp"
#include "privmx/endpoint/kvdb/KvdbException.hpp"
#include "privmx/endpoint/kvdb/Mapper.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"

using namespace privmx::endpoint;
using namespace kvdb;

KvdbApiImpl::KvdbApiImpl(
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
    const core::Connection& connection
) : _gateway(gateway),
    _userPrivKey(userPrivKey),
    _keyProvider(keyProvider),
    _host(host),
    _eventMiddleware(eventMiddleware),
    _connection(connection),
    _serverApi(ServerApi(gateway)),
    _kvdbProvider(KvdbProvider(
        [&](const std::string& id) {
            auto model = privmx::utils::TypedObjectFactory::createNewObject<server::KvdbGetModel>();
            model.kvdbId(id);
            auto serverKvdb = _serverApi.kvdbGet(model).kvdb();
            return serverKvdb;
        },
        std::bind(&KvdbApiImpl::validateKvdbDataIntegrity, this, std::placeholders::_1)
    )),
    _subscribeForKvdb(false),
    _kvdbSubscriptionHelper(core::SubscriptionHelper(eventChannelManager, "kvdb", "items"))
{
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&KvdbApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
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
    auto kvdbId = core::EndpointUtils::generateId();
    auto kvdbDIO = _connection.getImpl()->createDIOForNewContainer(
        contextId,
        kvdbId
    );
    auto kvdbCCN = _keyProvider->generateContainerControlNumber();
    KvdbDataToEncryptV5 kvdbDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::Buffer::from(kvdbCCN),
        .dio = kvdbDIO
    };
    auto create_kvdb_model = utils::TypedObjectFactory::createNewObject<server::KvdbCreateModel>();
    create_kvdb_model.kvdbId(kvdbId);
    create_kvdb_model.contextId(contextId);
    create_kvdb_model.keyId(kvdbKey.id);
    create_kvdb_model.data(_kvdbDataEncryptorV5.encrypt(kvdbDataToEncrypt, _userPrivKey, kvdbKey.key).asVar());
    auto allUsers = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    create_kvdb_model.keys(
        _keyProvider->prepareKeysList(
            allUsers, 
            kvdbKey, 
            kvdbDIO,
            kvdbCCN
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

    // read all key to check if all key belongs to this kvdb
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=currentKvdb.contextId(), .containerId=kvdbId};
    keyProviderRequest.addAll(currentKvdb.keys(), location);
    auto kvdbKeys {_keyProvider->getKeysAndVerify(keyProviderRequest).at(location)};
    auto currentKvdbEntry = currentKvdb.data().get(currentKvdb.data().size()-1);
    core::DecryptedEncKey currentKvdbKey;
    for (auto key : kvdbKeys) {
        if (currentKvdbEntry.keyId() == key.first) {
            currentKvdbKey = key.second;
            break;
        }
    }
    auto kvdbCCN = decryptKvdbInternalMeta(currentKvdbEntry, currentKvdbKey);
    for(auto key : kvdbKeys) {
        if(key.second.statusCode != 0 || (key.second.dataStructureVersion == 2 && key.second.containerControlNumber != kvdbCCN)) {
            throw KvdbEncryptionKeyValidationException();
        }
    }
    // setting kvdb Key adding new users
    core::EncKey kvdbKey = currentKvdbKey;
    core::DataIntegrityObject updateKvdbDio = _connection.getImpl()->createDIO(currentKvdb.contextId(), kvdbId);
    privmx::utils::List<core::server::KeyEntrySet> keys = utils::TypedObjectFactory::createNewList<core::server::KeyEntrySet>();
    if(needNewKey) {
        kvdbKey = _keyProvider->generateKey();
        keys = _keyProvider->prepareKeysList(
            new_users, 
            kvdbKey, 
            updateKvdbDio,
            kvdbCCN
        );
    }
    if(usersToAddMissingKey.size() > 0) {
        auto tmp = _keyProvider->prepareMissingKeysForNewUsers(
            kvdbKeys,
            usersToAddMissingKey, 
            updateKvdbDio, 
            kvdbKeys[0].containerControlNumber
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

    model.kvdbId(kvdbId);
    model.keyId(kvdbKey.id);
    model.keys(keys);
    model.users(usersList);
    model.managers(managersList);
    model.version(version);
    model.force(force);
    if (policies.has_value()) {
        model.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    KvdbDataToEncryptV5 kvdbDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::Buffer::from(kvdbCCN),
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
    if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateByValue(kvdb);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _getKvdbEx, data send)
    auto statusCode = validateKvdbDataIntegrity(kvdb);
    if(statusCode != 0) {
        if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateByValueAndStatus(kvdb, core::DataIntegrityStatus::ValidationFailed);
        return Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode};
    } else {
        if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateByValueAndStatus(kvdb, core::DataIntegrityStatus::ValidationSucceed);
    }
    auto result = decryptAndConvertKvdbDataToKvdb(kvdb);
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
    std::vector<Kvdb> kvdbs;
    for (size_t i = 0; i < kvdbsList.kvdbs().size(); i++) {
        auto kvdb = kvdbsList.kvdbs().get(i);
        if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateByValue(kvdb);
        auto statusCode = validateKvdbDataIntegrity(kvdb);
        kvdbs.push_back(Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode});
        if(statusCode == 0) {
            if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateByValueAndStatus(kvdb ,core::DataIntegrityStatus::ValidationSucceed);
        } else {
            if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateByValueAndStatus(kvdb ,core::DataIntegrityStatus::ValidationFailed);
            kvdbsList.kvdbs().remove(i);
            i--;
        }
    }
    auto tmp = decryptAndConvertKvdbsDataToKvdbs(kvdbsList.kvdbs());
    for(size_t j = 0, i = 0; i < kvdbs.size(); i++) {
        if(kvdbs[i].statusCode == 0) {
            kvdbs[i] = tmp[j];
            j++;
        }
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, _listKvdbsEx, data decrypted)
    return core::PagingList<Kvdb>({
        .totalAvailable = kvdbsList.count(),
        .readItems = kvdbs
    });
}

Item KvdbApiImpl::getItem(const std::string& kvdbId, const std::string& key) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, getItem)
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbItemGetModel>();
    model.kvdbId(kvdbId);
    model.kvdbItemKey(key);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getItem, getting item)
    auto item = _serverApi.kvdbItemGet(model).kvdbItem();
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getItem, data recived);
    privmx::endpoint::kvdb::server::KvdbInfo kvdb;
    Item result;
    try {
        PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getItem, getting kvdb)
        kvdb = getRawKvdbFromCacheOrBridge(kvdbId);
        PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getItem, decrypting item)
        auto statusCode = validateItemDataIntegrity(item);
        if(statusCode != 0) {
            PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, getItem, data integrity validation failed)
            result.statusCode = statusCode;
            return result;
        }
        result = decryptAndConvertItemDataToItem(kvdb, item);
    } catch (const core::Exception& e) {
        PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, getItem, data decrypted failed)
        result.statusCode = e.getCode();
        return result;
    }
    if (result.statusCode == 0) {
        std::vector<core::VerificationRequest> verifierInput {{
            .contextId = kvdb.contextId(),
            .senderId = result.info.author,
            .senderPubKey = result.authorPubKey,
            .date = result.info.createDate
        }};

        std::vector<bool> verified;
        try {
            verified = _connection.getImpl()->getUserVerifier()->verify(verifierInput);
        } catch (...) {
            throw core::UserVerificationMethodUnhandledException();
        }
        if (verified[0] == false) {
            result.statusCode = core::ExceptionConverter::getCodeOfUserVerificationFailureException();
        }
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, getItem, data decrypted)
    return result;
}

core::PagingList<std::string> KvdbApiImpl::listItemsKey(const std::string& kvdbId, const kvdb::KeysPagingQuery& pagingQuery) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, listItemKeys)
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbListKeysModel>();
    model.kvdbId(kvdbId);
    kvdb::Mapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listItemKeys, getting itemList)
    auto itemsList = _serverApi.kvdbListKeys(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listItemKeys, data send)
    std::vector<std::string> keys;
    for(auto key : itemsList.kvdbItemKeys()) {
        keys.push_back(key);
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, listItemKeys, data decrypted)
    return core::PagingList<std::string>({
        .totalAvailable = itemsList.count(),
        .readItems = keys
    });
}

core::PagingList<Item> KvdbApiImpl::listItems(const std::string& kvdbId, const kvdb::ItemsPagingQuery& pagingQuery) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, listItem)
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbListItemsModel>();
    model.kvdbId(kvdbId);
    kvdb::Mapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listItem, getting itemList)
    auto itemsList = _serverApi.kvdbListItems(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listItemKeys, data send)
    auto kvdb = itemsList.kvdb();
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listItemKeys, data send)
    auto items = decryptAndConvertItemsDataToItems(kvdb, itemsList.kvdbItems());
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, listItemKeys, data decrypted)
    return core::PagingList<Item>({
        .totalAvailable = itemsList.count(),
        .readItems = items
    });
}

void KvdbApiImpl::setItem(const std::string& kvdbId, const std::string& key, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data, int64_t version) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, sendItem);
    auto kvdb = getRawKvdbFromCacheOrBridge(kvdbId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, sendItem, getKvdb)
    auto msgKey = getKvdbCurrentEncKey(kvdb);
    auto  send_item_model = utils::TypedObjectFactory::createNewObject<server::KvdbItemSetModel>();
    send_item_model.kvdbId(kvdb.id());
    send_item_model.kvdbItemKey(key);
    send_item_model.version(version);
    send_item_model.keyId(msgKey.id);
    privmx::endpoint::core::DataIntegrityObject itemDIO = _connection.getImpl()->createDIO(
        kvdb.contextId(),
        kvdbId,
        key
    );
    ItemDataToEncryptV5 itemData {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .data = data,
        .internalMeta = std::nullopt,
        .dio = itemDIO
    };
    auto encryptedItemData = _itemDataEncryptorV5.encrypt(itemData, _userPrivKey, msgKey.key);
    send_item_model.kvdbItemValue(encryptedItemData.asVar());
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, sendItem, data encrypted)
    _serverApi.kvdbItemSet(send_item_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, sendItem, data send)
}

void KvdbApiImpl::deleteItem(const std::string& kvdbId, const std::string& key) {
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbItemDeleteModel>();
    model.kvdbId(kvdbId);
    model.kvdbItemKey(key);
    _serverApi.kvdbItemDelete(model);
}

std::map<std::string, bool> KvdbApiImpl::deleteItems(const std::string& kvdbId, const std::vector<std::string>& keys) {
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbItemDeleteManyModel>();
    model.kvdbId(kvdbId);
    model.kvdbItemKeys(utils::TypedObjectFactory::createNewList<std::string>());
    for(auto key : keys) {
    model.kvdbItemKeys().add(key);
    }
    auto deleteStatuses = _serverApi.kvdbItemDeleteMany(model).results();
    std::map<std::string, bool> result;
    for(auto deleteStatus : deleteStatuses) {
        result.insert(std::make_pair(deleteStatus.kvdbItemKey(), deleteStatus.status() == "OK"));
    }
    return result;
}

void KvdbApiImpl::processNotificationEvent(const std::string& type, const std::string& channel, const Poco::JSON::Object::Ptr& data) {
    if(!_kvdbSubscriptionHelper.hasSubscriptionForChannel(channel) && channel != INTERNAL_EVENT_CHANNEL_NAME) {
        return;
    }
    if (type == "kvdbCreated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbInfo>(data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            _kvdbProvider.updateByValue(raw);
            auto statusCode = validateKvdbDataIntegrity(raw);
            privmx::endpoint::kvdb::Kvdb data;
            if(statusCode == 0) {
                data = decryptAndConvertKvdbDataToKvdb(raw); 
            } else {
                data = Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode};
            }
            std::shared_ptr<KvdbCreatedEvent> event(new KvdbCreatedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbUpdated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbInfo>(data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            _kvdbProvider.updateByValue(raw);
            auto statusCode = validateKvdbDataIntegrity(raw);
            privmx::endpoint::kvdb::Kvdb data;
            if(statusCode == 0) {
                data = decryptAndConvertKvdbDataToKvdb(raw); 
            } else {
                data = Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode};
            }
            std::shared_ptr<KvdbUpdatedEvent> event(new KvdbUpdatedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbDeleted") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbDeletedEventData>(data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            _kvdbProvider.invalidateByContainerId(raw.kvdbId());
            auto data = Mapper::mapToKvdbDeletedEventData(raw);
            std::shared_ptr<KvdbDeletedEvent> event(new KvdbDeletedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbStats") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbStatsEventData>(data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            _kvdbProvider.updateStats(raw);
            auto data = Mapper::mapToKvdbStatsEventData(raw);
            std::shared_ptr<KvdbStatsChangedEvent> event(new KvdbStatsChangedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbNewItem") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbItemInfo>(data);
        auto data = decryptAndConvertItemDataToItem(raw);
        std::shared_ptr<KvdbNewItemEvent> event(new KvdbNewItemEvent());
        event->channel = channel;
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "kvdbUpdatedItem") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbItemInfo>(data);
        auto data = decryptAndConvertItemDataToItem(raw);
        std::shared_ptr<KvdbItemUpdatedEvent> event(new KvdbItemUpdatedEvent());
        event->channel = channel;
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "kvdbDeletedItem") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbDeletedItemEventData>(data);
        auto data = Mapper::mapToKvdbDeletedItemEventData(raw);
        std::shared_ptr<KvdbItemDeletedEvent> event(new KvdbItemDeletedEvent());
        event->channel = channel;
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "subscribe") {
        std::string channelName = data->has("channel") ? data->getValue<std::string>("channel") : "";
        if(channelName == "kvdb") {
            PRIVMX_DEBUG("KvdbApi", "Cache", "Enabled")
            _subscribeForKvdb = true;
        }
    } else if (type == "unsubscribe") {
        std::string channelName = data->has("channel") ?  data->getValue<std::string>("channel") : "";
        if(channelName == "kvdb") {
            PRIVMX_DEBUG("KvdbApi", "Cache", "Disabled")
            _subscribeForKvdb = false;
            _kvdbProvider.invalidate();
        }
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

void KvdbApiImpl::subscribeForItemEvents(std::string kvdbId) {
    assertKvdbExist(kvdbId);
    if(_kvdbSubscriptionHelper.hasSubscriptionForElement(kvdbId)) {
        throw AlreadySubscribedException(kvdbId);
    }
    _kvdbSubscriptionHelper.subscribeForElement(kvdbId);
}

void KvdbApiImpl::unsubscribeFromItemEvents(std::string kvdbId) {
    assertKvdbExist(kvdbId);
    if(!_kvdbSubscriptionHelper.hasSubscriptionForElement(kvdbId)) {
        throw NotSubscribedException(kvdbId);
    }
    _kvdbSubscriptionHelper.unsubscribeFromElement(kvdbId);
}

void KvdbApiImpl::processConnectedEvent() {
    _kvdbProvider.invalidate();
}

void KvdbApiImpl::processDisconnectedEvent() {
    _kvdbProvider.invalidate();
}

privmx::utils::List<std::string> KvdbApiImpl::mapUsers(const std::vector<core::UserWithPubKey>& users) {
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user : users) {
        result.add(user.userId);
    }
    return result;
}

DecryptedKvdbDataV5 KvdbApiImpl::decryptKvdbV5(server::KvdbDataEntry kvdbEntry, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedKvdbData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedKvdbDataV5>(kvdbEntry.data());
        if(encKey.statusCode != 0) {
            auto tmp = _kvdbDataEncryptorV5.extractPublic(encryptedKvdbData);
            tmp.statusCode = encKey.statusCode;
            return tmp;
        }
        return _kvdbDataEncryptorV5.decrypt(encryptedKvdbData, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedKvdbDataV5{{.dataStructureVersion = 5, .statusCode = e.getCode()}, {},{},{},{},{}};
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedKvdbDataV5{{.dataStructureVersion = 5, .statusCode = core::ExceptionConverter::convert(e).getCode()}, {},{},{},{},{}};
    } catch (...) {
        return DecryptedKvdbDataV5{{.dataStructureVersion = 5, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE}, {},{},{},{},{}};
    }
}

Kvdb KvdbApiImpl::convertDecryptedKvdbDataV5ToKvdb(server::KvdbInfo kvdbInfo, const DecryptedKvdbDataV5& kvdbData) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    for (auto x : kvdbInfo.users()) {
        users.push_back(x);
    }
    for (auto x : kvdbInfo.managers()) {
        managers.push_back(x);
    }

    return {
        .contextId = kvdbInfo.contextId(),
        .kvdbId = kvdbInfo.id(),
        .createDate = kvdbInfo.createDate(),
        .creator = kvdbInfo.creator(),
        .lastModificationDate = kvdbInfo.lastModificationDate(),
        .lastModifier = kvdbInfo.lastModifier(),
        .users = users,
        .managers = managers,
        .version = kvdbInfo.version(),
        .publicMeta = kvdbData.publicMeta,
        .privateMeta = kvdbData.privateMeta,
        .items = kvdbInfo.items(),
        .lastItemDate = kvdbInfo.lastItemDate(),
        .policy = core::Factory::parsePolicyServerObject(kvdbInfo.policy()), 
        .statusCode = kvdbData.statusCode
    };
}

std::tuple<Kvdb, core::DataIntegrityObject> KvdbApiImpl::decryptAndConvertKvdbDataToKvdb(server::KvdbInfo kvdb, server::KvdbDataEntry kvdbEntry, const core::DecryptedEncKey& encKey) {
    if (kvdbEntry.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(kvdbEntry.data());
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
                case 5: {
                    auto decryptedKvdbData = decryptKvdbV5(kvdbEntry, encKey);
                    return std::make_tuple(convertDecryptedKvdbDataV5ToKvdb(kvdb, decryptedKvdbData), decryptedKvdbData.dio);
                }
            }
        } 
    }
    auto e = UnknowKvdbFormatException();
    return std::make_tuple(Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode()}, core::DataIntegrityObject());
}


std::vector<Kvdb> KvdbApiImpl::decryptAndConvertKvdbsDataToKvdbs(privmx::utils::List<server::KvdbInfo> kvdbs) {
    std::vector<Kvdb> result;
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    //create request to KeyProvider for keys
    for (size_t i = 0; i < kvdbs.size(); i++) {
        auto kvdb = kvdbs.get(i);
        core::EncKeyLocation location{.contextId=kvdb.contextId(), .containerId=kvdb.id()};
        auto kvdb_data_entry = kvdb.data().get(kvdb.data().size()-1);
        keyProviderRequest.addOne(kvdb.keys(), kvdb_data_entry.keyId(), location);
    }
    //send request to KeyProvider
    auto kvdbKeys {_keyProvider->getKeysAndVerify(keyProviderRequest)};
    std::vector<core::DataIntegrityObject> kvdbsDIO;
    std::map<std::string, bool> duplication_check;
    for (size_t i = 0; i < kvdbs.size(); i++) {
        auto kvdb = kvdbs.get(i);
        try {
            auto tmp = decryptAndConvertKvdbDataToKvdb(
                kvdb, 
                kvdb.data().get(kvdb.data().size()-1), 
                kvdbKeys.at({.contextId=kvdb.contextId(), .containerId=kvdb.id()}).at(kvdb.data().get(kvdb.data().size()-1).keyId())
            );
            result.push_back(std::get<0>(tmp));
            auto kvdbDIO = std::get<1>(tmp);
            kvdbsDIO.push_back(kvdbDIO);
            //find duplication
            std::string fullRandomId = kvdbDIO.randomId + "-" + std::to_string(kvdbDIO.timestamp);
            if(duplication_check.find(fullRandomId) == duplication_check.end()) {
                duplication_check.insert(std::make_pair(fullRandomId, true));
            } else {
                result[result.size()-1].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result.push_back(Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode()});
            kvdbsDIO.push_back(core::DataIntegrityObject{});
        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (size_t i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            verifierInput.push_back({
                .contextId = result[i].contextId,
                .senderId = result[i].lastModifier,
                .senderPubKey = kvdbsDIO[i].creatorPubKey,
                .date = result[i].lastModificationDate
            });
        }
    }
    std::vector<bool> verified;
    try {
        verified =_connection.getImpl()->getUserVerifier()->verify(verifierInput);
    } catch (...) {
        throw core::UserVerificationMethodUnhandledException();
    }
    for (size_t j = 0, i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            result[i].statusCode = verified[j] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
            j++;
        }
    }
    return result;
}

Kvdb KvdbApiImpl::decryptAndConvertKvdbDataToKvdb(server::KvdbInfo kvdb) {
    auto kvdb_data_entry = kvdb.data().get(kvdb.data().size()-1);
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=kvdb.contextId(), .containerId=kvdb.id()};
    keyProviderRequest.addOne(kvdb.keys(), kvdb_data_entry.keyId(), location);
    auto encKey = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(kvdb_data_entry.keyId());
    Kvdb result;
    core::DataIntegrityObject kvdbDIO;
    std::tie(result, kvdbDIO) = decryptAndConvertKvdbDataToKvdb(kvdb, kvdb_data_entry, encKey);
    if(result.statusCode != 0) return result;
    std::vector<core::VerificationRequest> verifierInput {};
    verifierInput.push_back({
        .contextId = result.contextId,
        .senderId = result.lastModifier,
        .senderPubKey = kvdbDIO.creatorPubKey,
        .date = result.lastModificationDate
    });
    std::vector<bool> verified;
    try {
        verified =_connection.getImpl()->getUserVerifier()->verify(verifierInput);
    } catch (...) {
        throw core::UserVerificationMethodUnhandledException();
    }
    result.statusCode = verified[0] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    return result;
}


DecryptedItemDataV5 KvdbApiImpl::decryptItemDataV5(server::KvdbItemInfo item, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedItemData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedItemDataV5>(item.kvdbItemValue());
        if(encKey.statusCode != 0) {
            auto tmp = _itemDataEncryptorV5.extractPublic(encryptedItemData);
            tmp.statusCode = encKey.statusCode;
            return tmp;
        }
        return _itemDataEncryptorV5.decrypt(encryptedItemData, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedItemDataV5{{.dataStructureVersion = 5, .statusCode = e.getCode()}, {},{},{},{},{},{}};
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedItemDataV5{{.dataStructureVersion = 5, .statusCode = core::ExceptionConverter::convert(e).getCode()}, {},{},{},{},{},{}};
    } catch (...) {
        return DecryptedItemDataV5{{.dataStructureVersion = 5, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE}, {},{},{},{},{},{}};
    }
}

Item KvdbApiImpl::convertDecryptedItemDataV5ToItem(server::KvdbItemInfo item, DecryptedItemDataV5 itemData) {
    Item ret {
        .info = {
            .kvdbId = item.kvdbId(),
            .key = item.kvdbItemKey(),
            .createDate = item.createDate(),
            .author = item.author(),
        },
        .publicMeta = itemData.publicMeta, 
        .privateMeta = itemData.privateMeta,
        .data = itemData.data,
        .authorPubKey = itemData.authorPubKey,
        .version = item.version(),
        .statusCode = itemData.statusCode
    };
    return ret;
}

std::tuple<Item, core::DataIntegrityObject> KvdbApiImpl::decryptAndConvertItemDataToItem(server::KvdbItemInfo item, const core::DecryptedEncKey& encKey) {
    // If data is not string, then data is object and has version field
    // Solution with data as object is newer than data as base64 string
    if (item.kvdbItemValue().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(item.kvdbItemValue());
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
                case 5: {
                    auto decryptItem = decryptItemDataV5(item, encKey);
                    return std::make_tuple(convertDecryptedItemDataV5ToItem(item, decryptItem), decryptItem.dio);
                }
            }
        } 
    }
    auto e = UnknowItemFormatException();
    return std::make_tuple(Item{{},{},{},{},{},{},.statusCode = e.getCode()}, core::DataIntegrityObject());
}

std::vector<Item> KvdbApiImpl::decryptAndConvertItemsDataToItems(server::KvdbInfo kvdb, utils::List<server::KvdbItemInfo> items) {
   std::set<std::string> keyIds;
    for (auto item : items) {
        keyIds.insert(item.keyId());
    }
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=kvdb.contextId(), .containerId=kvdb.id()};
    keyProviderRequest.addMany(kvdb.keys(), keyIds, location);
    auto keyMap = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location);
    std::vector<Item> result;
    std::map<std::string, bool> duplication_check;
    for (auto item : items) {
        try {
            auto statusCode = validateItemDataIntegrity(item);
            if(statusCode == 0) {
                auto tmp = decryptAndConvertItemDataToItem(item, keyMap.at(item.keyId()));
                result.push_back(std::get<0>(tmp));
                auto itemDIO = std::get<1>(tmp);
                //find duplication
                std::string fullRandomId = itemDIO.randomId + "-" + std::to_string(itemDIO.timestamp);
                if(duplication_check.find(fullRandomId) == duplication_check.end()) {
                    duplication_check.insert(std::make_pair(fullRandomId, true));
                } else {
                    result[result.size()-1].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
                }
            } else {
                result.push_back(Item{{},{},{},{},{},{},.statusCode = statusCode});
            }
        } catch (const core::Exception& e) {
            result.push_back(Item{{},{},{},{},{},{},.statusCode = e.getCode()});
        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (auto item: result) {
        if(item.statusCode == 0) {
            verifierInput.push_back({
                .contextId = kvdb.contextId(),
                .senderId = item.info.author,
                .senderPubKey = item.authorPubKey,
                .date = item.info.createDate
            });
        }
    }
    std::vector<bool> verified;
    try {
        verified = _connection.getImpl()->getUserVerifier()->verify(verifierInput);
    } catch (...) {
        throw core::UserVerificationMethodUnhandledException();
    }
    for (size_t j = 0, i = 0; i < result.size(); ++i) {
        if (result[i].statusCode == 0) {
            result[i].statusCode = verified[j] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
            j++;
        }
    }
    return result;
}

Item KvdbApiImpl::decryptAndConvertItemDataToItem(server::KvdbInfo kvdb, server::KvdbItemInfo item) {
    auto keyId = item.keyId();
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=kvdb.contextId(), .containerId=kvdb.id()};
    keyProviderRequest.addOne(kvdb.keys(), keyId, location);
    auto encKey = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(keyId);
    Item result;
    core::DataIntegrityObject itemDIO;
    std::tie(result, itemDIO) = decryptAndConvertItemDataToItem(item, encKey);
    if(result.statusCode != 0) return result;
    std::vector<core::VerificationRequest> verifierInput {};
        verifierInput.push_back({
            .contextId = kvdb.contextId(),
            .senderId = result.info.author,
            .senderPubKey = result.authorPubKey,
            .date = result.info.createDate
        });
    std::vector<bool> verified;
    try {
        verified = _connection.getImpl()->getUserVerifier()->verify(verifierInput);
    } catch (...) {
        throw core::UserVerificationMethodUnhandledException();
    }
    result.statusCode = verified[0] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    return result;
}

Item KvdbApiImpl::decryptAndConvertItemDataToItem(server::KvdbItemInfo item) {
    try {
        auto kvdb = getRawKvdbFromCacheOrBridge(item.kvdbId());
        return decryptAndConvertItemDataToItem(kvdb, item);
    } catch (const core::Exception& e) {
        return Item{{},{},{},{},{},{},.statusCode = e.getCode()};
    } catch (const privmx::utils::PrivmxException& e) {
        return Item{{},{},{},{},{},{},.statusCode = e.getCode()};
    } catch (...) {
        return Item{{},{},{},{},{},{},.statusCode = ENDPOINT_CORE_EXCEPTION_CODE};
    }
}

std::string KvdbApiImpl::decryptKvdbInternalMeta(server::KvdbDataEntry kvdbEntry, const core::DecryptedEncKey& encKey) {
    if (kvdbEntry.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(kvdbEntry.data());
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
            case 4:
                return 0;
            case 5:
                return decryptKvdbV5(kvdbEntry, encKey).internalMeta.stdString();
            }
        } 
    } else if (kvdbEntry.data().isString()) {
        return 0;
    }
    throw UnknowKvdbFormatException();
    return 0;
}

core::DecryptedEncKey KvdbApiImpl::getKvdbCurrentEncKey(server::KvdbInfo kvdb) {
    auto kvdb_data_entry = kvdb.data().get(kvdb.data().size()-1);
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=kvdb.contextId(), .containerId=kvdb.id()};
    keyProviderRequest.addOne(kvdb.keys(), kvdb_data_entry.keyId(), location);
    return _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(kvdb_data_entry.keyId());
}

server::KvdbInfo KvdbApiImpl::getRawKvdbFromCacheOrBridge(const std::string& kvdbId) {
    // useing kvdbProvider only with KVDB_TYPE_FILTER_FLAG 
    // making sure to have valid cache
    if(!_subscribeForKvdb) _kvdbProvider.update(kvdbId);
    auto kvdbContainerInfo = _kvdbProvider.get(kvdbId);
    if(kvdbContainerInfo.status != core::DataIntegrityStatus::ValidationSucceed) {
        throw KvdbDataIntegrityException();
    }
    return kvdbContainerInfo.container;
}

void KvdbApiImpl::assertKvdbExist(const std::string& kvdbId) {
    //check if kvdb is in cache or on server
    getRawKvdbFromCacheOrBridge(kvdbId);
}

uint32_t KvdbApiImpl::validateKvdbDataIntegrity(server::KvdbInfo kvdb) {
    auto kvdb_data_entry = kvdb.data().get(kvdb.data().size()-1);
    if (kvdb_data_entry.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(kvdb_data_entry.data());
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
            case 4:
                return 0;
            case 5: 
                {
                    auto kvdb_data = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedKvdbDataV5>(kvdb_data_entry.data());
                    auto dio = _kvdbDataEncryptorV5.getDIOAndAssertIntegrity(kvdb_data);
                    if(
                        dio.contextId != kvdb.contextId() ||
                        dio.containerId != kvdb.id() ||
                        dio.creatorUserId != kvdb.lastModifier() ||
                        !core::TimestampValidator::validate(dio.timestamp, kvdb.lastModificationDate())
                    ) { 
                        return KvdbDataIntegrityException().getCode();
                    }
                    return 0;
                }
            }
        } 
    } else if(kvdb_data_entry.data().isString()) {
        return 0;
    }
    return UnknowKvdbFormatException().getCode();
}

uint32_t KvdbApiImpl::validateItemDataIntegrity(server::KvdbItemInfo item) {
    auto item_data = item.kvdbItemValue();
    if (item_data.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(item_data);
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
            case 4:
                return 0;
            case 5: 
                {
                    auto encData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedItemDataV5>(item_data);
                    auto dio = _itemDataEncryptorV5.getDIOAndAssertIntegrity(encData);
                    std::cout << dio.containerId << " " << item.kvdbId() << std::endl;
                    std::cout << dio.contextId << " " << item.contextId() << std::endl;
                    std::cout << dio.itemId.value() << " " << item.kvdbItemKey() << std::endl;
                    std::cout << dio.creatorUserId << " " << item.lastModifier() << std::endl;
                    if(
                        dio.containerId != item.kvdbId() ||
                        dio.contextId != item.contextId() ||
                        !dio.itemId.has_value() || dio.itemId.value() != item.kvdbItemKey() ||
                        dio.creatorUserId != item.lastModifier() ||
                        !core::TimestampValidator::validate(dio.timestamp, item.lastModificationDate())
                    ) {
                        return ItemDataIntegrityException().getCode();
                    }
                    return 0;
                }
            }
        }
    } else if(item_data.isString()) {
        return 0;
    }
    return UnknowItemFormatException().getCode();
}


