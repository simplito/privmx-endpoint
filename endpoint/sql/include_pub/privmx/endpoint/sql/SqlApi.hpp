/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_SQL_SQLAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_SQL_SQLAPI_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/sql/Types.hpp"
#include "privmx/endpoint/core/ExtendedPointer.hpp"
#include "privmx/endpoint/sql/DatabaseHandle.hpp"

namespace privmx {
namespace endpoint {
namespace sql {

class SqlApiImpl;

/**
 * 'SqlApi' is a class representing Endpoint's API for SQL databases.
 */
class SqlApi : public privmx::endpoint::core::ExtendedPointer<SqlApiImpl>
{
public:
    /**
     * Creates an instance of 'SqlApi'.
     *
     * @param connection instance of 'Connection'
     *
     * @return SearchApi object
     */
    static SqlApi create(core::Connection& connection, store::StoreApi& storeApi, kvdb::KvdbApi& kvdbApi);

    /**
     * //doc-gen:ignore
     */
    SqlApi();
    SqlApi(const SqlApi& obj);
    SqlApi& operator=(const SqlApi& obj);
    SqlApi(SqlApi&& obj);
    ~SqlApi();

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
    SqlApi(const std::shared_ptr<SqlApiImpl>& impl);
};

}  // namespace sql
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SQL_SQLAPI_HPP_
