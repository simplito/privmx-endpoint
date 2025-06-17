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

    /**
     * Creates a new Kvdb in given Context.
     *
     * @param contextId ID of the Context to create the Kvdb in
     * @param users array of UserWithPubKey structs which indicates who will have access to the created Kvdb
     * @param managers array of UserWithPubKey structs which indicates who will have access (and management rights) to the created Kvdb
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param policies Kvdb's policies
     * @return ID of the created Kvdb
     */
    std::string createKvdb(const std::string& contextId, 
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers, 
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta, 
        const std::optional<core::ContainerPolicy>& policies = std::nullopt
    );

    /**
     * Updates an existing Kvdb.
     *
     * @param kvdbId ID of the Kvdb to update
     * @param users array of UserWithPubKey structs which indicates who will have access to the created Kvdb
     * @param managers array of UserWithPubKey structs which indicates who will have access (and management rights) to the created Kvdb
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param version current version of the updated Kvdb
     * @param force force update (without checking version)
     * @param forceGenerateNewKey force to regenerate a key for the Kvdb
     * @param policies Kvdb's policies
     */    
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

    /**
     * Deletes a Kvdb by given Kvdb ID.
     *
     * @param kvdbId ID of the Kvdb to delete
     */
    void deleteKvdb(const std::string& kvdbId);

    /**
     * Gets a Kvdb by given Kvdb ID.
     *
     * @param kvdbId ID of Kvdb to get
     * @return struct containing info about the Kvdb
     */
    Kvdb getKvdb(const std::string& kvdbId);

    /**
     * Gets a list of Kvdbs in given Context.
     *
     * @param contextId ID of the Context to get the Kvdbs from
     * @param pagingQuery with list query parameters
     * @return struct containing a list of Kvdbs
     */    
    core::PagingList<Kvdb> listKvdbs(const std::string& contextId, const core::PagingQuery& pagingQuery);

    /**
     * Gets a kvdb entry by given kvdb entry key and kvdb ID.
     *
     * @param kvdbId kvdb ID of the kvdb entry to get
     * @param key key of the kvdb entry to get
     * @return struct containing the kvdb entry
     */    
    KvdbEntry getEntry(const std::string& kvdbId, const std::string& key);

    /**
     * Gets a list of kvdb entries keys from a Kvdb.
     *
     * @param kvdbId ID of the Kvdb to list kvdb entries from
     * @param pagingQuery with list query parameters
     * @return struct containing a list of kvdb entries
     */    
    core::PagingList<std::string> listEntriesKeys(const std::string& kvdbId, const core::PagingQuery& pagingQuery);

    /**
     * Gets a list of kvdb entries from a Kvdb.
     *
     * @param kvdbId ID of the Kvdb to list kvdb entries from
     * @param pagingQuery  with list query parameters
     * @return struct containing a list of kvdb entries
     */    
    core::PagingList<KvdbEntry> listEntries(const std::string& kvdbId, const core::PagingQuery& pagingQuery);

    /**
     * Sets a kvdb entry in the given Kvdb.
     * @param kvdbId ID of the Kvdb to set the entry to
     * @param key kvdb entry key
     * @param publicMeta public kvdb entry metadata
     * @param privateMeta private kvdb entry metadata
     * @param data content of the kvdb entry
     * @return ID of the new kvdb entry
     */    
    void setEntry(const std::string& kvdbId, const std::string& key, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data, int64_t version);
    
    /**
     * Deletes a kvdb entry by given kvdb entry ID.
     *
     * @param kvdbId kvdb ID of the kvdb entry to delete
     * @param key key of the kvdb entry to delete
     */    
    void deleteEntry(const std::string& kvdbId, const std::string& key);

    /**
     * Deletes a kvdb entries by given kvdb ID and the list of entries keys.
     *
     * @param kvdbId ID of the kvdb database to delete from
     * @param keys vector of the keys of the kvdb entries to delete
     * @return map with the statuses of deletion for every key
     */    
    std::map<std::string, bool> deleteEntries(const std::string& kvdbId, const std::vector<std::string>& keys);

    /**
     * Subscribes for the Kvdb module main events.
     */
    void subscribeForKvdbEvents();
    
    /**
     * Unsubscribes from the Kvdb module main events.
     */
    void unsubscribeFromKvdbEvents();

    /**
     * Subscribes for events in given Kvdb.
     * @param ID of the Kvdb to subscribe
     */    
    void subscribeForEntryEvents(std::string kvdbId);

    /**
     * Unsubscribes from events in given Kvdb.
     * @param {string} kvdbId ID of the Kvdb to unsubscribe
     */    
    void unsubscribeFromEntryEvents(std::string kvdbId);

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
