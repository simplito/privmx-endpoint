/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_SQL_SQLAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_SQL_SQLAPIIMPL_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/sql/Types.hpp"

#include "privmx/endpoint/search/FullTextSearch.hpp"

#include "privmx/utils/ThreadSaveMap.hpp"
#include "privmx/endpoint/sql/SqlException.hpp"
#include "privmx/endpoint/sql/DynamicTypes.hpp"
#include "privmx/endpoint/sql/SqlTypes.hpp"
#include "privmx/utils/ManualManagedClass.hpp"
#include "privmx/endpoint/sql/DatabaseHandle.hpp"

namespace privmx {
namespace endpoint {
namespace sql {

class SqlApiImpl : public privmx::utils::ManualManagedClass<SqlApiImpl>
{
public:
    SqlApiImpl(
        const core::Connection& connection,
        const store::StoreApi& storeApi,
        const kvdb::KvdbApi& kvdbApi
    );
    ~SqlApiImpl();

    std::string createSqlDatabase(const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
                                const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta,
                                const core::Buffer& privateMeta, const std::optional<core::ContainerPolicy>& policies = std::nullopt);

    void updateSqlDatabase(const std::string& sqlDatabaseId, const std::vector<core::UserWithPubKey>& users,
                        const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                        const int64_t version, const bool force, const bool forceGenerateNewKey, const std::optional<core::ContainerPolicy>& policies = std::nullopt);

    void deleteSqlDatabase(const std::string& sqlDatabaseId);

    SqlDatabase getSqlDatabase(const std::string& sqlDatabaseId);

    core::PagingList<SqlDatabase> listSqlDatabases(const std::string& contextId, const core::PagingQuery& pagingQuery);

    std::shared_ptr<DatabaseHandle> openSqlDatabase(const std::string& sqlDatabaseId);

private:
    static const std::string SQL_TYPE_FILTER_FLAG;

    dynamic::SqlData getSqlData(const std::string& sqlDatabaseId);
    void setSqlData(const std::string& sqlDatabaseId, const std::string& storeId);
    SqlDatabase mapSqlDatabase(const kvdb::Kvdb& kvdb);
    std::vector<SqlDatabase> mapSqlDatabases(const std::vector<kvdb::Kvdb>& kvdbs);

    core::Connection _connection;
    store::StoreApi _storeApi;
    kvdb::KvdbApi _kvdbApi;
    
};

}  // namespace sql
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SQL_SQLAPIIMPL_HPP_
