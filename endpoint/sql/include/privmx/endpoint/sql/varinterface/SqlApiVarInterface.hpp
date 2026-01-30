/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_SQL_SQLAPIVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_SQL_SQLAPIVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/core/VarDeserializer.hpp"
#include "privmx/endpoint/sql/SqlApi.hpp"
#include "privmx/endpoint/sql/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace sql {

class SqlApiVarInterface {
public:
    enum METHOD {
        Create = 0,
        CreateSqlDatabase = 1,
        UpdateSqlDatabase = 2,
        DeleteSqlDatabase = 3,
        GetSqlDatabase = 4,
        ListSqlDatabases = 5,
        OpenSqlDatabase = 6,
        DatabaseHandleBeginTransaction = 7,
        DatabaseHandleQuery = 8,
        DatabaseHandleClose = 9,
        FreeDatabaseHandle = 10,
        TransactionQuery = 11,
        TransactionCommit = 12,
        TransactionRollback = 13,
        FreeTransaction = 14,
        QueryBindInt64 = 15,
        QueryBindDouble = 16,
        QueryBindText = 17,
        QueryBindBlob = 18,
        QueryBindNull = 19,
        QueryStep = 20,
        QueryReset = 21,
        FreeQuery = 22,
        RowGetStatus = 23,
        RowGetColumnCount = 24,
        RowGetColumn = 25,
        FreeRow = 26,
        ColumnGetName = 27,
        ColumnGetType = 28,
        ColumnGetInt64 = 29,
        ColumnGetDouble = 30,
        ColumnGetText = 31,
        ColumnGetBlob = 32,
        FreeColumn = 33,
    };

    SqlApiVarInterface(core::Connection connection, store::StoreApi storeApi, kvdb::KvdbApi kvdbApi, const core::VarSerializer& serializer)
        : _connection(std::move(connection)), _storeApi(std::move(storeApi)), _kvdbApi(std::move(kvdbApi)), _serializer(serializer) {}

    Poco::Dynamic::Var create(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createSqlDatabase(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateSqlDatabase(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteSqlDatabase(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getSqlDatabase(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listSqlDatabases(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var openSqlDatabase(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var databaseHandleBeginTransaction(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var databaseHandleQuery(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var databaseHandleClose(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var freeDatabaseHandle(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var transactionQuery(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var transactionCommit(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var transactionRollback(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var freeTransaction(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var queryBindInt64(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var queryBindDouble(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var queryBindText(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var queryBindBlob(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var queryBindNull(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var queryStep(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var queryReset(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var freeQuery(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var rowGetStatus(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var rowGetColumnCount(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var rowGetColumn(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var freeRow(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var columnGetName(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var columnGetType(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var columnGetInt64(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var columnGetDouble(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var columnGetText(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var columnGetBlob(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var freeColumn(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

    SqlApi getApi() const { return _sqlApi; }

private:
    static std::map<METHOD, Poco::Dynamic::Var (SqlApiVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::Connection _connection;
    store::StoreApi _storeApi;
    kvdb::KvdbApi _kvdbApi;
    SqlApi _sqlApi;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace sql
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SQL_SQLAPIVARINTERFACE_HPP_
