#include "privmx/endpoint/sql/DatabaseHandleImpl.hpp"

#include "privmx/endpoint/search/PrivmxSqliteVFS.hpp"
#include "privmx/endpoint/sql/SqlException.hpp"
#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::sql;

std::shared_ptr<DatabaseHandle> DatabaseHandleImpl::open(const std::string& filename) {
    sqlite3* db;
    int rc;

    rc = sqlite3_vfs_register(search::sqlite3_privmxvfs(), 1);
    if(rc) {
        throw DatabaseVFSRegisterException(sqlite3_errmsg(db));
    }

    rc = sqlite3_open(filename.c_str(), &db);
    if(rc) {
        throw DatabaseOpenException(sqlite3_errmsg(db));
    }
    std::shared_ptr<sqlite3> db2 = std::shared_ptr<sqlite3>(db, sqlite3_close);

    sqlite3_busy_timeout(db, 10000);

    return std::make_shared<DatabaseHandleImpl>(db2);
}

DatabaseHandleImpl::DatabaseHandleImpl(std::shared_ptr<sqlite3> db) : _db(std::move(db)) { }

std::shared_ptr<Transaction> DatabaseHandleImpl::beginTransaction() {
    return TransactionImpl::create(_db);
}

std::shared_ptr<Query> DatabaseHandleImpl::query(const std::string& sqlQuery) {
    return QueryImpl::create(_db, sqlQuery);
}

void DatabaseHandleImpl::close() {
    _db.reset();
}

std::shared_ptr<TransactionImpl> TransactionImpl::create(std::shared_ptr<sqlite3> db) {
    char* error = NULL;
    auto result = sqlite3_exec(db.get(), "BEGIN TRANSACTION;", NULL, NULL, &error);
    if(result != SQLITE_OK) {
        LOG_ERROR("TransactionImpl::create::error:", error);
        throw SQLEvaluationException("Recived SQLITE_ERROR with code: "+ std::to_string(result));
    }
    return std::make_shared<TransactionImpl>(db);
}

TransactionImpl::TransactionImpl(std::shared_ptr<sqlite3> db) : _db(std::move(db)) { }

std::shared_ptr<Query> TransactionImpl::query(const std::string& sqlQuery) {
    return QueryImpl::create(_db, sqlQuery);
}

void TransactionImpl::commit() {
    char* error = NULL;
    auto result = sqlite3_exec(_db.get(), "COMMIT;", NULL, NULL, &error);
    if(result != SQLITE_OK) {
        LOG_ERROR("TransactionImpl::commit::error:", error);
        throw SQLEvaluationException("Recived SQLITE_ERROR with code: "+ std::to_string(result));
    }
}

void TransactionImpl::rollback() {
    char* error = NULL;
    auto result = sqlite3_exec(_db.get(), "ROLLBACK;", NULL, NULL, &error);
    if(result != SQLITE_OK) {
        LOG_ERROR("TransactionImpl::rollback::error:", error);
        throw SQLEvaluationException("Recived SQLITE_ERROR with code: "+ std::to_string(result));
    }
}

std::shared_ptr<QueryImpl> QueryImpl::create(std::shared_ptr<sqlite3> db, const std::string& sqlQuery) {
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db.get(), sqlQuery.c_str(), sqlQuery.size(), &stmt, NULL);
    return std::make_shared<QueryImpl>(db, std::shared_ptr<sqlite3_stmt>(stmt, sqlite3_finalize));
}

QueryImpl::QueryImpl(std::shared_ptr<sqlite3> db, std::shared_ptr<sqlite3_stmt> stmt)
    : _db(std::move(db)), _stmt(std::move(stmt)) { }

void QueryImpl::bindInt64(int64_t index, int64_t value) {
    sqlite3_bind_int64(_stmt.get(), index, value);
}

void QueryImpl::bindDouble(int64_t index, double value) {
    sqlite3_bind_double(_stmt.get(), index, value);
}

void QueryImpl::bindText(int64_t index, const std::string& value) {
    sqlite3_bind_text(_stmt.get(), index, value.c_str(), value.size(), SQLITE_TRANSIENT);
}

void QueryImpl::bindBlob(int64_t index, const core::Buffer& value) {
    sqlite3_bind_blob64(_stmt.get(), index, value.data(), value.size(), SQLITE_TRANSIENT);
}

void QueryImpl::bindNull(int64_t index) {
    sqlite3_bind_null(_stmt.get(), index);
}

std::shared_ptr<Row> QueryImpl::step() {
    auto status = sqlite3_step(_stmt.get());
    if(status == SQLITE_OK && status != SQLITE_ROW && status != SQLITE_DONE) {
        LOG_ERROR(sqlite3_errmsg(_db.get()));
    }
    return std::make_shared<RowImpl>(_stmt, status, sqlite3_errmsg(_db.get()));
    
}

void QueryImpl::reset() {
    sqlite3_reset(_stmt.get());
}

void QueryImpl::finalize() {
    _stmt.reset();
}

RowImpl::RowImpl(std::shared_ptr<sqlite3_stmt> stmt, int status, std::string statusDescription) : 
    _stmt(std::move(stmt)), _status(status), _statusDescription(statusDescription) {}

EvaluationStatus RowImpl::getStatus() {
    if (_status == SQLITE_ROW) {
        return {T_ROW, _statusDescription};
    } else if (_status == SQLITE_DONE) {
        return {T_DONE, _statusDescription};
    } else if (_status == SQLITE_BUSY) {
        return {T_BUSY, _statusDescription};
    } else if (_status == SQLITE_MISUSE) {
        return {T_MISUSE, _statusDescription};
    }
    return {T_ERROR, _statusDescription};
}

int64_t RowImpl::getColumnCount() {
    return sqlite3_column_count(_stmt.get());
}

std::shared_ptr<Column> RowImpl::getColumn(int64_t index) {
    return std::make_shared<ColumnImpl>(_stmt, index);
}

ColumnImpl::ColumnImpl(std::shared_ptr<sqlite3_stmt> stmt, int index) : _stmt(std::move(stmt)), _index(index) { }

std::string ColumnImpl::getName() {
    return sqlite3_column_name(_stmt.get(), _index);
}

DataType ColumnImpl::getType() {
    int type = sqlite3_column_type(_stmt.get(), _index);
    switch (type) {
        case SQLITE_INTEGER:
            return T_INTEGER;
        case SQLITE_FLOAT:
            return T_DOUBLE;
        case SQLITE_TEXT:
            return T_TEXT;
        case SQLITE_BLOB:
            return T_BLOB;
        case SQLITE_NULL:
        default:
            return T_NULL;
    }
}

int64_t ColumnImpl::getInt64() {
    return sqlite3_column_int64(_stmt.get(), _index);
}

double ColumnImpl::getDouble() {
    return sqlite3_column_double(_stmt.get(), _index);
}

std::string ColumnImpl::getText() {
    auto size = sqlite3_column_bytes(_stmt.get(), _index);
    auto data = sqlite3_column_text(_stmt.get(), _index);
    return std::string(reinterpret_cast<const char*>(data), size);
}

core::Buffer ColumnImpl::getBlob() {
    auto size = sqlite3_column_bytes(_stmt.get(), _index);
    auto data = sqlite3_column_blob(_stmt.get(), _index);
    return core::Buffer::from(reinterpret_cast<const char*>(data), size);
}
