/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_SQL_DATABASEHANDLEIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_SQL_DATABASEHANDLEIMPL_HPP_

#include <memory>
#include <sqlite3.h>

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/sql/DatabaseHandle.hpp"

namespace privmx {
namespace endpoint {
namespace sql {

class DatabaseHandleImpl : public DatabaseHandle
{
public:
    static std::shared_ptr<DatabaseHandle> open(const std::string& filename);
    DatabaseHandleImpl(std::shared_ptr<sqlite3> db);
    ~DatabaseHandleImpl() override = default;
    std::shared_ptr<Transaction> beginTransaction() override;
    std::shared_ptr<Query> query(const std::string& sqlQuery) override;
    void close() override;

private:
    std::shared_ptr<sqlite3> _db;
};

class TransactionImpl : public Transaction
{
public:
    static std::shared_ptr<TransactionImpl> create(std::shared_ptr<sqlite3> db);
    TransactionImpl(std::shared_ptr<sqlite3> db);
    ~TransactionImpl() override = default;
    std::shared_ptr<Query> query(const std::string& sqlQuery) override;
    void commit() override;
    void rollback() override;

private:
    std::shared_ptr<sqlite3> _db;
};

class QueryImpl : public Query
{
public:
    static std::shared_ptr<QueryImpl> create(std::shared_ptr<sqlite3> db, const std::string& sqlQuery);
    QueryImpl(std::shared_ptr<sqlite3> db, std::shared_ptr<sqlite3_stmt> stmt);
    ~QueryImpl() override = default;
    void bindInt64(int64_t index, int64_t value) override;
    void bindDouble(int64_t index, double value) override;
    void bindText(int64_t index, const std::string& value) override;
    void bindBlob(int64_t index, const core::Buffer& value) override;
    void bindNull(int64_t index) override;
    std::shared_ptr<Row> step() override;
    void reset() override;
    void finalize() override;

private:
    std::shared_ptr<sqlite3> _db;
    std::shared_ptr<sqlite3_stmt> _stmt;
};

class RowImpl : public Row
{
public:
    RowImpl(std::shared_ptr<sqlite3_stmt> stmt, int status, std::string statusDescription);
    ~RowImpl() override = default;
    EvaluationStatus getStatus() override;
    int64_t getColumnCount() override;
    std::shared_ptr<Column> getColumn(int64_t index) override;

private:
    std::shared_ptr<sqlite3_stmt> _stmt;
    int _status;
    std::string _statusDescription;
};

class ColumnImpl : public Column
{
public:
    ColumnImpl(std::shared_ptr<sqlite3_stmt> stmt, int index);
    ~ColumnImpl() override = default;
    std::string getName() override;
    DataType getType() override;
    int64_t getInt64() override;
    double getDouble() override;
    std::string getText() override;
    core::Buffer getBlob() override;

private:
    std::shared_ptr<sqlite3_stmt> _stmt;
    int _index;
};


}  // namespace sql
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SQL_DATABASEHANDLEIMPL_HPP_
