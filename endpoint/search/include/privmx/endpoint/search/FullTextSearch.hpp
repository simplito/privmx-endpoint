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
#include <string>
#include <vector>

#include <sqlite3.h>

#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/search/Types.hpp"

namespace privmx {
namespace endpoint {
namespace search {

class FullTextSearch
{
public:
    static std::shared_ptr<FullTextSearch> openDb(const std::string& filename, const IndexMode mode);
    FullTextSearch(std::shared_ptr<sqlite3> db, const IndexMode mode);
    int64_t addDocument(const std::string& name, const std::string& content);
    void updateDocument(const Document& document);
    void deleteDocument(const int64_t documentId);
    core::PagingList<Document> search(const std::string& query, const core::PagingQuery& pagingQuery);
    void ensureTableCreated();
    void createTable();
    void close();

private:
    int64_t getCount(const std::string& query, const core::PagingQuery& pagingQuery);

    std::shared_ptr<sqlite3> _db;
    IndexMode _mode;
};

}  // namespace search
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SEARCH_FULLTEXTSEARCH_HPP_
