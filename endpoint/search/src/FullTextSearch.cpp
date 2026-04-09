/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdexcept>

#include "privmx/endpoint/search/FullTextSearch.hpp"
#include "privmx/endpoint/search/PrivmxFS.hpp"
#include "privmx/endpoint/search/PrivmxSqliteVFS.hpp"
#include "privmx/endpoint/search/SearchException.hpp"
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::search;

std::shared_ptr<FullTextSearch> FullTextSearch::openDb(const std::string& filename, const IndexMode mode) {
    sqlite3* db;
    int rc;

    rc = sqlite3_vfs_register(sqlite3_privmxvfs(), 1);
    if(rc) {
        throw DatabaseVFSRegisterException();
    }

    rc = sqlite3_open(":memory:", &db);
    if(rc) {
        throw DatabaseOpenException();
    }
    std::shared_ptr<sqlite3> db2 = std::shared_ptr<sqlite3>(db, sqlite3_close);

    sqlite3_busy_timeout(db, 10000);

    rc = sqlite3_exec(db, (std::string("ATTACH 'file:") + filename + "?vfs=privmxvfs' AS pmx;").c_str(), 0, 0, 0);
    if(rc != SQLITE_OK){
        throw DatabaseAttachException(sqlite3_errmsg(db));
    }

    return std::make_shared<FullTextSearch>(db2, filename, mode);
}

FullTextSearch::FullTextSearch(std::shared_ptr<sqlite3> db, std::string filename, const IndexMode mode)
    : _db(std::move(db)), _filename(std::move(filename)), _mode(mode) {}

int64_t FullTextSearch::addDocument(const std::string& name, const std::string& content) {
    NewDocument document;
    document.name = name;
    document.content = content;
    auto result = addDocuments({document});
    return result.front();
}

std::vector<int64_t> FullTextSearch::addDocuments(const std::vector<NewDocument>& documents) {
    if (documents.empty()) {
        return {};
    }

    PrivmxFS::beginDbOperation(_filename);
    const char* beginSql = "BEGIN IMMEDIATE;";
    const char* commitSql = "COMMIT;";
    const char* rollbackSql = "ROLLBACK;";
    const char* insertSql = "INSERT INTO pmx.documents (name, content) VALUES (?, ?);";
    sqlite3_stmt* stmt = nullptr;
    bool transactionStarted = false;
    std::vector<int64_t> rowIds;
    rowIds.reserve(documents.size());
    try {
        if (sqlite3_exec(_db.get(), beginSql, nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw InsertExecuteException(sqlite3_errmsg(_db.get()));
        }
        transactionStarted = true;

        if (sqlite3_prepare_v2(_db.get(), insertSql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw InsertPrepareException(sqlite3_errmsg(_db.get()));
        }

        for (const auto& document : documents) {
            sqlite3_bind_text(stmt, 1, document.name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, document.content.c_str(), -1, SQLITE_TRANSIENT);

            int status = sqlite3_step(stmt);
            if (status != SQLITE_DONE) {
                sqlite3_finalize(stmt);
                stmt = nullptr;
                throw InsertExecuteException(sqlite3_errmsg(_db.get()));
            }

            rowIds.push_back(sqlite3_last_insert_rowid(_db.get()));
            if (sqlite3_reset(stmt) != SQLITE_OK) {
                sqlite3_finalize(stmt);
                stmt = nullptr;
                throw InsertExecuteException(sqlite3_errmsg(_db.get()));
            }
            sqlite3_clear_bindings(stmt);
        }

        sqlite3_finalize(stmt);
        stmt = nullptr;
        if (sqlite3_exec(_db.get(), commitSql, nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw InsertExecuteException(sqlite3_errmsg(_db.get()));
        }
        PrivmxFS::endDbOperation(_filename);
        return rowIds;
    } catch (...) {
        if (stmt != nullptr) {
            sqlite3_finalize(stmt);
        }
        if (transactionStarted) {
            sqlite3_exec(_db.get(), rollbackSql, nullptr, nullptr, nullptr);
        }
        PrivmxFS::endDbOperation(_filename);
        throw;
    }
}

Document FullTextSearch::getDocument(const int64_t documentId) {
    Document result;
    const char* searchSql = "SELECT rowid, name, content FROM pmx.documents WHERE rowid=?;";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(_db.get(), searchSql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw SelectPrepareException(sqlite3_errmsg(_db.get()));
    }

    sqlite3_bind_int64(stmt, 1, documentId);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Document document;
        sqlite3_int64 rowid = sqlite3_column_int64(stmt, 0);
        document.documentId = rowid;
        const unsigned char* text = sqlite3_column_text(stmt, 1);
        if (text) {
            document.name = reinterpret_cast<const char*>(text);
        }
        const unsigned char* text2 = sqlite3_column_text(stmt, 2);
        if (text2) {
            document.content = reinterpret_cast<const char*>(text2);
        }

        result = document;
    }

    sqlite3_finalize(stmt);

    return result;
}

core::PagingList<Document> FullTextSearch::listDocuments(const core::PagingQuery& pagingQuery) {
    std::vector<Document> results;
    const char* searchSql = "SELECT rowid, name, content FROM pmx.documents LIMIT ? OFFSET ?;";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(_db.get(), searchSql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw SelectPrepareException(sqlite3_errmsg(_db.get()));
    }

    sqlite3_bind_int64(stmt, 1, pagingQuery.limit);
    sqlite3_bind_int64(stmt, 2, pagingQuery.skip);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Document document;
        sqlite3_int64 rowid = sqlite3_column_int64(stmt, 0);
        document.documentId = rowid;
        const unsigned char* text = sqlite3_column_text(stmt, 1);
        if (text) {
            document.name = reinterpret_cast<const char*>(text);
        }
        const unsigned char* text2 = sqlite3_column_text(stmt, 2);
        if (text2) {
            document.content = reinterpret_cast<const char*>(text2);
        }

        results.push_back(document);
    }

    sqlite3_finalize(stmt);

    return {getCountOfAll(), results};
}

void FullTextSearch::updateDocument(const Document& document) {
    const char* updateSql = "UPDATE pmx.documents SET name=?, content=? WHERE rowid=?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(_db.get(), updateSql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw UpdatePrepareException(sqlite3_errmsg(_db.get()));
    }

    sqlite3_bind_text(stmt, 1, document.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, document.content.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, document.documentId);

    int status = sqlite3_step(stmt);
    if (status != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw UpdateExecuteException(sqlite3_errmsg(_db.get()));
    }

    int64_t rowsUpdated = sqlite3_changes64(_db.get());

    sqlite3_finalize(stmt);

    if (rowsUpdated == 0) {
        throw InvalidDocumentIdException();
    }
}

void FullTextSearch::deleteDocument(const int64_t documentId) {
    const char* deleteSql = "DELETE FROM pmx.documents WHERE rowid=?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(_db.get(), deleteSql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw DeletePrepareException(sqlite3_errmsg(_db.get()));
    }

    sqlite3_bind_int64(stmt, 1, documentId);

    int status = sqlite3_step(stmt);
    if (status != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw DeleteExecuteException(sqlite3_errmsg(_db.get()));
    }

    int64_t rowsDeleted = sqlite3_changes64(_db.get());

    sqlite3_finalize(stmt);

    if (rowsDeleted == 0) {
        throw InvalidDocumentIdException();
    }
}

core::PagingList<Document> FullTextSearch::search(const std::string& query, const core::PagingQuery& pagingQuery) {
    std::vector<Document> results;
    const char* searchSql = "SELECT rowid, name, content FROM pmx.documents WHERE documents MATCH ? LIMIT ? OFFSET ?;";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(_db.get(), searchSql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw SelectPrepareException(sqlite3_errmsg(_db.get()));
    }

    sqlite3_bind_text(stmt, 1, query.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, pagingQuery.limit);
    sqlite3_bind_int64(stmt, 3, pagingQuery.skip);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Document document;
        sqlite3_int64 rowid = sqlite3_column_int64(stmt, 0);
        document.documentId = rowid;
        const unsigned char* text = sqlite3_column_text(stmt, 1);
        if (text) {
            document.name = reinterpret_cast<const char*>(text);
        }
        const unsigned char* text2 = sqlite3_column_text(stmt, 2);
        if (text2) {
            document.content = reinterpret_cast<const char*>(text2);
        }

        results.push_back(document);
    }

    sqlite3_finalize(stmt);

    return {getCount(query), results};
}

void FullTextSearch::ensureTableCreated() {
    try {
        createTable();
    }  catch (const privmx::endpoint::core::Exception& e) {
        LOG_ERROR("FullTextSearch::ensureTableCreated() recived endpoint::core::Exception ->\n", e.getFull())
    } catch (const privmx::utils::PrivmxException& e) {
        LOG_ERROR("FullTextSearch::ensureTableCreated() recived utils::PrivmxException, converter to endpoint::core::Exception:->\n", core::ExceptionConverter::convert(e).getFull())
    } catch (const std::exception& e) {
        LOG_FATAL("FullTextSearch::ensureTableCreated() recived std::exception->\n", e.what())
    } catch (...) {
        LOG_FATAL("FullTextSearch::ensureTableCreated() recived unknown exception\n")
    }
}

void FullTextSearch::createTable() {
    const char* createTableSql1 = R"(
        CREATE VIRTUAL TABLE IF NOT EXISTS pmx.documents
        USING fts5(name UNINDEXED, content, tokenize='unicode61');
    )";
    const char* createTableSql2 = R"(
        CREATE VIRTUAL TABLE IF NOT EXISTS pmx.documents
        USING fts5(name UNINDEXED, content, content='', contentless_unindexed=1, tokenize='unicode61');
    )";
    const char* createTableSql = _mode == IndexMode::WITH_CONTENT ? createTableSql1 : createTableSql2;
    char* err = nullptr;
    if (sqlite3_exec(_db.get(), createTableSql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err;
        sqlite3_free(err);
        throw TableCreationException(msg);
    }
}

void FullTextSearch::close() {
    _db.reset();
}

int64_t FullTextSearch::getCount(const std::string& query) {
    sqlite3_stmt* stmt;

    const char* sql =
        "SELECT count(*) "
        "FROM pmx.documents "
        "WHERE documents MATCH ?;";

    if (sqlite3_prepare_v2(_db.get(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw SelectPrepareException(sqlite3_errmsg(_db.get()));
    }

    sqlite3_bind_text(stmt, 1, query.c_str(), -1, SQLITE_TRANSIENT);

    int64_t resultCount = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        resultCount = sqlite3_column_int64(stmt, 0);
    }

    sqlite3_finalize(stmt);

    return resultCount;
}

int64_t FullTextSearch::getCountOfAll() {
    sqlite3_stmt* stmt;

    const char* sql =
        "SELECT count(*) "
        "FROM pmx.documents;";

    if (sqlite3_prepare_v2(_db.get(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw SelectPrepareException(sqlite3_errmsg(_db.get()));
    }

    int64_t resultCount = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        resultCount = sqlite3_column_int64(stmt, 0);
    }

    sqlite3_finalize(stmt);

    return resultCount;
}
