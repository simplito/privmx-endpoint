/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/sql/varinterface/SqlApiVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/sql/VarDeserializer.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"
#include "privmx/endpoint/sql/VarSerializer.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::sql;

std::map<SqlApiVarInterface::METHOD, Poco::Dynamic::Var (SqlApiVarInterface::*)(const Poco::Dynamic::Var&)>
    SqlApiVarInterface::methodMap = {{Create, &SqlApiVarInterface::create},
                                        {CreateSqlDatabase, &SqlApiVarInterface::createSqlDatabase},
                                        {UpdateSqlDatabase, &SqlApiVarInterface::updateSqlDatabase},
                                        {DeleteSqlDatabase, &SqlApiVarInterface::deleteSqlDatabase},
                                        {GetSqlDatabase, &SqlApiVarInterface::getSqlDatabase},
                                        {ListSqlDatabases, &SqlApiVarInterface::listSqlDatabases},
                                        {OpenSqlDatabase, &SqlApiVarInterface::openSqlDatabase},
                                        {DatabaseHandleBeginTransaction, &SqlApiVarInterface::databaseHandleBeginTransaction},
                                        {DatabaseHandleQuery, &SqlApiVarInterface::databaseHandleQuery},
                                        {DatabaseHandleClose, &SqlApiVarInterface::databaseHandleClose},
                                        {FreeDatabaseHandle, &SqlApiVarInterface::freeDatabaseHandle},
                                        {TransactionQuery, &SqlApiVarInterface::transactionQuery},
                                        {TransactionCommit, &SqlApiVarInterface::transactionCommit},
                                        {TransactionRollback, &SqlApiVarInterface::transactionRollback},
                                        {FreeTransaction, &SqlApiVarInterface::freeTransaction},
                                        {QueryBindInt64, &SqlApiVarInterface::queryBindInt64},
                                        {QueryBindDouble, &SqlApiVarInterface::queryBindDouble},
                                        {QueryBindText, &SqlApiVarInterface::queryBindText},
                                        {QueryBindBlob, &SqlApiVarInterface::queryBindBlob},
                                        {QueryBindNull, &SqlApiVarInterface::queryBindNull},
                                        {QueryStep, &SqlApiVarInterface::queryStep},
                                        {QueryReset, &SqlApiVarInterface::queryReset},
                                        {QueryFinalize, &SqlApiVarInterface::queryFinalize},
                                        {FreeQuery, &SqlApiVarInterface::freeQuery},
                                        {RowGetStatus, &SqlApiVarInterface::rowGetStatus},
                                        {RowGetColumnCount, &SqlApiVarInterface::rowGetColumnCount},
                                        {RowGetColumn, &SqlApiVarInterface::rowGetColumn},
                                        {FreeRow, &SqlApiVarInterface::freeRow},
                                        {ColumnGetName, &SqlApiVarInterface::columnGetName},
                                        {ColumnGetType, &SqlApiVarInterface::columnGetType},
                                        {ColumnGetInt64, &SqlApiVarInterface::columnGetInt64},
                                        {ColumnGetDouble, &SqlApiVarInterface::columnGetDouble},
                                        {ColumnGetText, &SqlApiVarInterface::columnGetText},
                                        {ColumnGetBlob, &SqlApiVarInterface::columnGetBlob},
                                        {FreeColumn, &SqlApiVarInterface::freeColumn}};

Poco::Dynamic::Var SqlApiVarInterface::create(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _sqlApi = SqlApi::create(_connection, _storeApi, _kvdbApi);
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::createSqlDatabase(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 6);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr->get(5), "policies");
    auto result = _sqlApi.createSqlDatabase(contextId, users, managers, publicMeta, privateMeta, policies);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SqlApiVarInterface::updateSqlDatabase(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 9);
    auto sqlDatabaseId = _deserializer.deserialize<std::string>(argsArr->get(0), "sqlDatabaseId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto version = _deserializer.deserialize<int64_t>(argsArr->get(5), "version");
    auto force = _deserializer.deserialize<bool>(argsArr->get(6), "force");
    auto forceGenerateNewKey = _deserializer.deserialize<bool>(argsArr->get(7), "forceGenerateNewKey");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr->get(8), "policies");
    _sqlApi.updateSqlDatabase(sqlDatabaseId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::deleteSqlDatabase(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto sqlDatabaseId = _deserializer.deserialize<std::string>(argsArr->get(0), "sqlDatabaseId");
    _sqlApi.deleteSqlDatabase(sqlDatabaseId);
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::getSqlDatabase(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto sqlDatabaseId = _deserializer.deserialize<std::string>(argsArr->get(0), "sqlDatabaseId");
    auto result = _sqlApi.getSqlDatabase(sqlDatabaseId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SqlApiVarInterface::listSqlDatabases(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    auto result = _sqlApi.listSqlDatabases(contextId, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SqlApiVarInterface::openSqlDatabase(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto sqlDatabaseId = _deserializer.deserialize<std::string>(argsArr->get(0), "sqlDatabaseId");
    auto result = _sqlApi.openSqlDatabase(sqlDatabaseId);
    auto pointer = new std::shared_ptr(result);
    return _serializer.serialize(pointer);
}

Poco::Dynamic::Var SqlApiVarInterface::databaseHandleBeginTransaction(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto databaseHandle = _deserializer.deserializePointer<DatabaseHandle>(argsArr->get(0), "pointer");
    auto result = (*databaseHandle)->beginTransaction();
    auto pointer = new std::shared_ptr(result);
    return _serializer.serialize(pointer);
}

Poco::Dynamic::Var SqlApiVarInterface::databaseHandleQuery(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto databaseHandle = _deserializer.deserializePointer<DatabaseHandle>(argsArr->get(0), "pointer");
    auto query = _deserializer.deserialize<std::string>(argsArr->get(1), "query");
    auto result = (*databaseHandle)->query(query);
    auto pointer = new std::shared_ptr(result);
    return _serializer.serialize(pointer);
}

Poco::Dynamic::Var SqlApiVarInterface::databaseHandleClose(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto databaseHandle = _deserializer.deserializePointer<DatabaseHandle>(argsArr->get(0), "pointer");
    (*databaseHandle)->close();
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::freeDatabaseHandle(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto databaseHandle = _deserializer.deserializePointer<DatabaseHandle>(argsArr->get(0), "pointer");
    delete databaseHandle;
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::transactionQuery(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto transaction = _deserializer.deserializePointer<Transaction>(argsArr->get(0), "pointer");
    auto query = _deserializer.deserialize<std::string>(argsArr->get(1), "query");
    auto result = (*transaction)->query(query);
    auto pointer = new std::shared_ptr(result);
    return _serializer.serialize(pointer);
}

Poco::Dynamic::Var SqlApiVarInterface::transactionCommit(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto transaction = _deserializer.deserializePointer<Transaction>(argsArr->get(0), "pointer");
    (*transaction)->commit();
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::transactionRollback(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto transaction = _deserializer.deserializePointer<Transaction>(argsArr->get(0), "pointer");
    (*transaction)->rollback();
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::freeTransaction(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto transaction = _deserializer.deserializePointer<Transaction>(argsArr->get(0), "pointer");
    delete transaction;
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::queryBindInt64(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto query = _deserializer.deserializePointer<Query>(argsArr->get(0), "pointer");
    auto index = _deserializer.deserialize<int64_t>(argsArr->get(1), "index");
    auto value = _deserializer.deserialize<int64_t>(argsArr->get(2), "value");
    (*query)->bindInt64(index, value);
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::queryBindDouble(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto query = _deserializer.deserializePointer<Query>(argsArr->get(0), "pointer");
    auto index = _deserializer.deserialize<int64_t>(argsArr->get(1), "index");
    auto value = _deserializer.deserialize<double>(argsArr->get(2), "value");
    (*query)->bindDouble(index, value);
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::queryBindText(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto query = _deserializer.deserializePointer<Query>(argsArr->get(0), "pointer");
    auto index = _deserializer.deserialize<int64_t>(argsArr->get(1), "index");
    auto value = _deserializer.deserialize<std::string>(argsArr->get(2), "value");
    (*query)->bindText(index, value);
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::queryBindBlob(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto query = _deserializer.deserializePointer<Query>(argsArr->get(0), "pointer");
    auto index = _deserializer.deserialize<int64_t>(argsArr->get(1), "index");
    auto value = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "value");
    (*query)->bindBlob(index, value);
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::queryBindNull(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto query = _deserializer.deserializePointer<Query>(argsArr->get(0), "pointer");
    auto index = _deserializer.deserialize<int64_t>(argsArr->get(1), "index");
    (*query)->bindNull(index);
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::queryStep(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto query = _deserializer.deserializePointer<Query>(argsArr->get(0), "pointer");
    auto result = (*query)->step();
    auto pointer = new std::shared_ptr(result);
    return _serializer.serialize(pointer);
}

Poco::Dynamic::Var SqlApiVarInterface::queryReset(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto query = _deserializer.deserializePointer<Query>(argsArr->get(0), "pointer");
    (*query)->reset();
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::queryFinalize(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto query = _deserializer.deserializePointer<Query>(argsArr->get(0), "pointer");
    (*query)->finalize();
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::freeQuery(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto query = _deserializer.deserializePointer<Query>(argsArr->get(0), "pointer");
    delete query;
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::rowGetStatus(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto row = _deserializer.deserializePointer<Row>(argsArr->get(0), "pointer");
    auto result = (*row)->getStatus();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SqlApiVarInterface::rowGetColumnCount(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto row = _deserializer.deserializePointer<Row>(argsArr->get(0), "pointer");
    auto result = (*row)->getColumnCount();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SqlApiVarInterface::rowGetColumn(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto row = _deserializer.deserializePointer<Row>(argsArr->get(0), "pointer");
    auto index = _deserializer.deserialize<int64_t>(argsArr->get(1), "index");
    auto result = (*row)->getColumn(index);
    auto pointer = new std::shared_ptr(result);
    return _serializer.serialize(pointer);
}

Poco::Dynamic::Var SqlApiVarInterface::freeRow(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto row = _deserializer.deserializePointer<Row>(argsArr->get(0), "pointer");
    delete row;
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::columnGetName(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto column = _deserializer.deserializePointer<Column>(argsArr->get(0), "pointer");
    auto result = (*column)->getName();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SqlApiVarInterface::columnGetType(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto column = _deserializer.deserializePointer<Column>(argsArr->get(0), "pointer");
    auto result = (*column)->getType();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SqlApiVarInterface::columnGetInt64(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto column = _deserializer.deserializePointer<Column>(argsArr->get(0), "pointer");
    auto result = (*column)->getInt64();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SqlApiVarInterface::columnGetDouble(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto column = _deserializer.deserializePointer<Column>(argsArr->get(0), "pointer");
    auto result = (*column)->getDouble();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SqlApiVarInterface::columnGetText(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto column = _deserializer.deserializePointer<Column>(argsArr->get(0), "pointer");
    auto result = (*column)->getText();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SqlApiVarInterface::columnGetBlob(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto column = _deserializer.deserializePointer<Column>(argsArr->get(0), "pointer");
    auto result = (*column)->getBlob();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SqlApiVarInterface::freeColumn(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto column = _deserializer.deserializePointer<Column>(argsArr->get(0), "pointer");
    delete column;
    return {};
}

Poco::Dynamic::Var SqlApiVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
