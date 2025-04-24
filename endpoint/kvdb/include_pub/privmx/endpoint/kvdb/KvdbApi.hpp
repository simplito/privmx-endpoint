#ifndef _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPI_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <map>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/kvdb/Types.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {

class KvdbApiImpl;

/**
 * 'KvdbApi' is a class representing Endpoint's API for Kvdbs and their messages.
 */
class KvdbApi {
public:
    /**
     * Creates an instance of 'KvdbApi'.
     * 
     * @param connection instance of 'Connection'
     * 
     * @return KvdbApi object
     */
    static KvdbApi create(core::Connection& connetion);

    /**
     * //doc-gen:ignore
     */
    KvdbApi() = default;

    std::string createKvdb(const std::string& contextId, 
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers, 
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta, 
        const std::optional<core::ContainerPolicy>& policies = std::nullopt
    );
    void updateKvdb(const std::string& kvdbId, 
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers, 
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta,
        const int64_t version, 
        const bool force, 
        const bool forceGenerateNewKey, 
        const std::optional<core::ContainerPolicy>& policies = std::nullopt
    );
    void deleteKvdb(const std::string& kvdbId);
    Kvdb getKvdb(const std::string& kvdbId);
    core::PagingList<Kvdb> listKvdbs(const std::string& contextId, const core::PagingQuery& pagingQuery);

    KvdbEntry getEntry(const std::string& kvdbId, const std::string& key);
    core::PagingList<std::string> listEntriesKeys(const std::string& kvdbId, const kvdb::KvdbKeysPagingQuery& pagingQuery);
    core::PagingList<Item> listEntries(const std::string& kvdbId, const kvdb::KvdbEntryPagingQuery& pagingQuery);
    void setEntry(const std::string& kvdbId, const std::string& key, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data, int64_t version);
    void deleteEntry(const std::string& kvdbId, const std::string& key);
    std::map<std::string, bool> deleteEntries(const std::string& kvdbId, const std::vector<std::string>& keys);

    void subscribeForKvdbEvents();
    void unsubscribeFromKvdbEvents();
    void subscribeForEntriesEvents(std::string kvdbId);
    void unsubscribeFromEntriesEvents(std::string kvdbId);

    std::shared_ptr<KvdbApiImpl> getImpl() const { return _impl; }
private:
    void validateEndpoint();
    KvdbApi(const std::shared_ptr<KvdbApiImpl>& impl);
    std::shared_ptr<KvdbApiImpl> _impl;
};

}  // namespace kvdb
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPI_HPP_
