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
#include "privmx/endpoint/search/PrivmxSqliteVFS.hpp"
#include "privmx/endpoint/search/SearchException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::search;

std::shared_ptr<FullTextSearch> FullTextSearch::openDb(const std::string& filename, const IndexMode mode) {
    sqlite3* db;
    int rc;

    rc = sqlite3_vfs_register(sqlite3_privmxvfs(), 1);
    if(rc) {
        fprintf(stderr, "Can't register vfs: %s\n", sqlite3_errmsg(db));
        return {};
    }

    rc = sqlite3_open(":memory:", &db);
    if(rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return {};
    }
    std::shared_ptr<sqlite3> db2 = std::shared_ptr<sqlite3>(db, sqlite3_close);

    rc = sqlite3_exec(db, (std::string("ATTACH 'file:") + filename + "?vfs=privmxvfs' AS pmx;").c_str(), 0, 0, 0);
    if(rc != SQLITE_OK){
        fprintf(stderr, "ATTACH failed: %s\n", sqlite3_errmsg(db));
        return {};
    }

    return std::make_shared<FullTextSearch>(db2, mode);
}

FullTextSearch::FullTextSearch(std::shared_ptr<sqlite3> db, const IndexMode mode) : _db(std::move(db)), _mode(mode) {}

int64_t FullTextSearch::addDocument(const std::string& name, const std::string& content) {
    const char* insertSql = "INSERT INTO pmx.documents (name, content) VALUES (?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(_db.get(), insertSql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(_db.get()));
    }

    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, content.c_str(), -1, SQLITE_TRANSIENT);

    int status = sqlite3_step(stmt);
    if (status != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Błąd wykonania INSERT");
    }

    sqlite3_finalize(stmt);

    return sqlite3_last_insert_rowid(_db.get());
}

void FullTextSearch::updateDocument(const Document& document) {
    const char* updateSql = "UPDATE pmx.documents SET name=?, content=? WHERE rowid=?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(_db.get(), updateSql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(_db.get()));
    }

    sqlite3_bind_text(stmt, 1, document.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, document.content.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, document.documentId);

    int status = sqlite3_step(stmt);
    if (status != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Błąd wykonania UPDATE");
    }

    sqlite3_finalize(stmt);
}

void FullTextSearch::deleteDocument(const int64_t documentId) {
    const char* deleteSql = "DELETE FROM pmx.documents WHERE rowid=?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(_db.get(), deleteSql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(_db.get()));
    }

    sqlite3_bind_int64(stmt, 1, documentId);

    int status = sqlite3_step(stmt);
    if (status != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Błąd wykonania DELETE");
    }

    sqlite3_finalize(stmt);
}
#include <iostream>
core::PagingList<Document> FullTextSearch::search(const std::string& query, const core::PagingQuery& pagingQuery) {
    std::vector<Document> results;
    const char* searchSql = "SELECT rowid, name, content FROM pmx.documents WHERE documents MATCH ?;";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(_db.get(), searchSql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << sqlite3_errmsg(_db.get()) << std::endl;
        throw std::runtime_error("Błąd prepare SELECT");
    }

    sqlite3_bind_text(stmt, 1, query.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Document document;
        sqlite3_int64 rowid = sqlite3_column_int64(stmt, 0);
            document.documentId = rowid;
        const unsigned char* text = sqlite3_column_text(stmt, 1);
        if (text)
            document.name = reinterpret_cast<const char*>(text);
        const unsigned char* text2 = sqlite3_column_text(stmt, 2);
        if (text2)
            document.content = reinterpret_cast<const char*>(text2);

        results.push_back(document);
    }

    sqlite3_finalize(stmt);

    // return {results.size(), results};
    return {getCount(query, pagingQuery), results};
}

void FullTextSearch::ensureTableCreated() {
    try {
        createTable();
    } catch (...) {}
}
#include <iostream>
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

    std::cerr << createTableSql << std::endl;

    char* err = nullptr;
    if (sqlite3_exec(_db.get(), createTableSql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err;
        sqlite3_free(err);
        throw std::runtime_error("Błąd przy tworzeniu tabeli: " + msg);
    }
}

void FullTextSearch::close() {
    _db.reset();
}

int64_t FullTextSearch::getCount(const std::string& query, const core::PagingQuery& pagingQuery) {
    sqlite3_stmt* stmt;

    const char* sql =
        "SELECT count(*) "
        "FROM pmx.documents "
        "WHERE documents MATCH ?;";

    if (sqlite3_prepare_v2(_db.get(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Błąd przygotowania zapytania: " << sqlite3_errmsg(_db.get()) << std::endl;
        return -1;
    }

    sqlite3_bind_text(stmt, 1, query.c_str(), -1, SQLITE_TRANSIENT);

    int64_t resultCount = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        resultCount = sqlite3_column_int64(stmt, 0);
    }

    sqlite3_finalize(stmt);

    return resultCount;
}
