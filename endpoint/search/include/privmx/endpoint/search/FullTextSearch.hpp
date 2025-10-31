/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_FULLTEXTSEARCH_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_FULLTEXTSEARCH_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/search/Types.hpp"

#include <sqlite3.h>

#include <exception>
#include <stdexcept>
#include <iostream>

#include "privmx/endpoint/search/PrivmxSqliteVFS.hpp"

namespace privmx {
namespace endpoint {
namespace search {

class FullTextSearch
{
public:

    static std::shared_ptr<FullTextSearch> openDb(const std::string& filename) {
        sqlite3* db;
        int rc;

        rc = sqlite3_vfs_register(&PrivmxVfs, 1);
        if(rc) {
            fprintf(stderr, "Can't register vfs: %s\n", sqlite3_errmsg(db));
            return {};
        }

        rc = sqlite3_open(":memory:", &db);
        if(rc) {
            fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
            return {};
        }

        rc = sqlite3_exec(db, (std::string("ATTACH 'file:") + filename + "?vfs=memdb' AS pmx;").c_str(), 0, 0, 0);
        if(rc != SQLITE_OK){
            fprintf(stderr, "ATTACH failed: %s\n", sqlite3_errmsg(db));
            return {};
        }

        std::shared_ptr<sqlite3> db2 = std::shared_ptr<sqlite3>(db, sqlite3_close);
        return std::make_shared<FullTextSearch>(db2);
    }

    FullTextSearch(std::shared_ptr<sqlite3> db) : _db(std::move(db)) {}

    void addDocument(const std::string& resourceId, const std::string& content) {
        const char* insertSql = "INSERT INTO pmx.documents (resource_id, content) VALUES (?, ?);";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(_db.get(), insertSql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Błąd prepare INSERT");
        }

        sqlite3_bind_text(stmt, 1, resourceId.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, content.c_str(), -1, SQLITE_TRANSIENT);

        int status = sqlite3_step(stmt);
        if (status != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            std::cerr << status << std::endl;
            throw std::runtime_error("Błąd wykonania INSERT");
        }

        sqlite3_finalize(stmt);
    }

    std::vector<Document> search(const std::string& query) {
        std::vector<Document> results;
        const char* searchSql = "SELECT rowid, resource_id, content FROM pmx.documents WHERE documents MATCH ?;";

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(_db.get(), searchSql, -1, &stmt, nullptr) != SQLITE_OK) {
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
        return results;
    }

    void ensureTableCreated() {
        try {
            createTable();
        } catch (...) {}
    }

    void createTable() {
        const char* createTableSql = R"(
            CREATE VIRTUAL TABLE IF NOT EXISTS pmx.documents
            USING fts5(resource_id, content, tokenize='unicode61');
        )";

        char* err = nullptr;
        if (sqlite3_exec(_db.get(), createTableSql, nullptr, nullptr, &err) != SQLITE_OK) {
            std::string msg = err;
            sqlite3_free(err);
            throw std::runtime_error("Błąd przy tworzeniu tabeli: " + msg);
        }
    }

    void close() {
        _db.reset();
    }

private:
    std::shared_ptr<sqlite3> _db;
    
};

}  // namespace search
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SEARCH_FULLTEXTSEARCH_HPP_
