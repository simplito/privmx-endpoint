/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/sql/SqlApiImpl.hpp"
// #include "privmx/endpoint/search/PrivmxFS.hpp"
#include "privmx/utils/ThreadSaveMap.hpp"
#include "privmx/endpoint/sql/SqlException.hpp"

#include "privmx/endpoint/sql/DynamicTypes.hpp"
#include "privmx/utils/Utils.hpp"
#include "privmx/utils/TypedObject.hpp"

#include "privmx/endpoint/store/StoreApiImpl.hpp"
#include "privmx/endpoint/kvdb/KvdbApiImpl.hpp"

#include "privmx/endpoint/sql/DatabaseHandleImpl.hpp"
#include "privmx/endpoint/search/PrivmxFS.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::sql;

const std::string SqlApiImpl::SQL_TYPE_FILTER_FLAG = "sql";

core::Buffer serializeSqlData(const dynamic::SqlData& sqlData) {
    return core::Buffer::from(privmx::utils::Utils::stringifyVar(sqlData));
}

dynamic::SqlData deserializeSqlData(const core::Buffer& buf) {
    auto json = privmx::utils::Utils::parseJson(buf.stdString());
    return privmx::utils::TypedObjectFactory::createObjectFromVar<dynamic::SqlData>(json);
}

SqlApiImpl::SqlApiImpl(
        const core::Connection& connection,
        const store::StoreApi& storeApi,
        const kvdb::KvdbApi& kvdbApi
) {
    _connection = connection;
    _storeApi = storeApi;
    _kvdbApi = kvdbApi;
}

SqlApiImpl::~SqlApiImpl() { }

std::string SqlApiImpl::createSqlDatabase(
    const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta,
    const core::Buffer& privateMeta, const std::optional<core::ContainerPolicy>& policies
) {
    std::string sqlDatabaseId = _kvdbApi.getImpl()->createKvdbEx(contextId, users, managers, publicMeta, privateMeta, SQL_TYPE_FILTER_FLAG, policies);
    std::string storeId = _storeApi.getImpl()->createStoreEx(contextId, users, managers, {}, {}, SQL_TYPE_FILTER_FLAG, policies);
    setSqlData(sqlDatabaseId, storeId);
    return sqlDatabaseId;
}

void SqlApiImpl::updateSqlDatabase(
    const std::string& sqlDatabaseId, const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
    const int64_t version, const bool force, const bool forceGenerateNewKey, const std::optional<core::ContainerPolicy>& policies
) {
    auto data = getSqlData(sqlDatabaseId);
    _kvdbApi.getImpl()->updateKvdb(sqlDatabaseId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    _storeApi.getImpl()->updateStore(data.storeId(), users, managers, {}, {}, version, force, forceGenerateNewKey, policies);
}

void SqlApiImpl::deleteSqlDatabase(const std::string& sqlDatabaseId) {
    auto data = getSqlData(sqlDatabaseId);
    _kvdbApi.getImpl()->deleteKvdb(sqlDatabaseId);
    _storeApi.getImpl()->deleteStore(data.storeId());
}

SqlDatabase SqlApiImpl::getSqlDatabase(const std::string& sqlDatabaseId) {
    auto kvdb = _kvdbApi.getImpl()->getKvdbEx(sqlDatabaseId, SQL_TYPE_FILTER_FLAG);
    return mapSqlDatabase(kvdb);
}

core::PagingList<SqlDatabase> SqlApiImpl::listSqlDatabases(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    auto kvdbs = _kvdbApi.getImpl()->listKvdbsEx(contextId, pagingQuery, SQL_TYPE_FILTER_FLAG);
    return { .totalAvailable = kvdbs.totalAvailable, mapSqlDatabases(kvdbs.readItems) };
}

std::shared_ptr<DatabaseHandle> SqlApiImpl::openSqlDatabase(const std::string& sqlDatabaseId) {
    auto data = getSqlData(sqlDatabaseId);
    auto session = search::SessionManager::get()->addSession(_connection, _storeApi, _kvdbApi, sqlDatabaseId, data.storeId());
    std::string filename = "/pmx/" + session->id + "/index.db";
    return DatabaseHandleImpl::open(filename);
}

dynamic::SqlData SqlApiImpl::getSqlData(const std::string& sqlDatabaseId) {
    auto data = _kvdbApi.getImpl()->getEntry(sqlDatabaseId, "data");
    return deserializeSqlData(data.data);
}

void SqlApiImpl::setSqlData(const std::string& indexId, const std::string& storeId) {
    auto indexData = privmx::utils::TypedObjectFactory::createNewObject<dynamic::SqlData>();
    indexData.storeId(storeId);
    _kvdbApi.getImpl()->setEntry(indexId, "data", {}, {}, serializeSqlData(indexData), 0);
}

SqlDatabase SqlApiImpl::mapSqlDatabase(const kvdb::Kvdb& kvdb) {
    return SqlDatabase {
        .contextId = kvdb.contextId,
        .sqlDatabaseId = kvdb.kvdbId,
        .createDate = kvdb.createDate,
        .creator = kvdb.creator,
        .lastModificationDate = kvdb.lastModificationDate,
        .lastModifier = kvdb.lastModifier,
        .users = kvdb.users,
        .managers = kvdb.managers,
        .version = kvdb.version,
        .publicMeta = kvdb.publicMeta,
        .privateMeta = kvdb.privateMeta,
        .policy = kvdb.policy,
        .statusCode = kvdb.statusCode,
        .schemaVersion = kvdb.schemaVersion
    };
}

std::vector<SqlDatabase> SqlApiImpl::mapSqlDatabases(const std::vector<kvdb::Kvdb>& kvdbs) {
    std::vector<SqlDatabase> results;
    results.resize(kvdbs.size());
    for (std::size_t i = 0; i < kvdbs.size(); ++i) {
        results[i] = mapSqlDatabase(kvdbs[i]);
    }
    return results;
}
