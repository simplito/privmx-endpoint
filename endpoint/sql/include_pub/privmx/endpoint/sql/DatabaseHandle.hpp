/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_SQL_DATABASEHANDLE_HPP_
#define _PRIVMXLIB_ENDPOINT_SQL_DATABASEHANDLE_HPP_

#include <memory>

#include "privmx/endpoint/core/Buffer.hpp"

namespace privmx {
namespace endpoint {
namespace sql {

enum DataType : int64_t
{
    T_INTEGER = 1,
    T_DOUBLE = 2,
    T_TEXT = 3,
    T_BLOB = 4,
    T_NULL = 5,
};

enum EvaluationStatus : int64_t
{
    T_ERROR = 0,
    T_ROW = 1,
    T_DONE = 2,
};

class Column
{
public:
    virtual ~Column() = default;
    virtual std::string getName() = 0;
    virtual DataType getType() = 0;
    virtual int64_t getInt64() = 0;
    virtual double getDouble() = 0;
    virtual std::string getText() = 0;
    virtual core::Buffer getBlob() = 0;
};

class Row
{
public:
    virtual ~Row() = default;
    virtual EvaluationStatus getStatus() = 0;
    virtual int64_t getColumnCount() = 0;
    virtual std::shared_ptr<Column> getColumn(int64_t index) = 0;
};

class Query
{
public:
    virtual ~Query() = default;
    virtual void bindInt64(int64_t index, int64_t value) = 0;
    virtual void bindDouble(int64_t index, double value) = 0;
    virtual void bindText(int64_t index, const std::string& value) = 0;
    virtual void bindBlob(int64_t index, const core::Buffer& value) = 0;
    virtual void bindNull(int64_t index) = 0;
    virtual std::shared_ptr<Row> step() = 0;
    virtual void reset() = 0;
};

class Transaction
{
public:
    virtual ~Transaction() = default;
    virtual std::shared_ptr<Query> query(const std::string& sqlQuery) = 0;
    virtual void commit() = 0;
    virtual void rollback() = 0;
};

class DatabaseHandle
{
public:
    virtual ~DatabaseHandle() = default;
    virtual std::shared_ptr<Transaction> beginTransaction() = 0;
    virtual std::shared_ptr<Query> query(const std::string& sqlQuery) = 0;
    virtual void close() = 0;
};

}  // namespace sql
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SQL_DATABASEHANDLE_HPP_
