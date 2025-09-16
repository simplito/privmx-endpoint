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
     * Creates a new KVDB in given Context.
     *
     * @param contextId ID of the Context to create the KVDB in
     * @param users array of UserWithPubKey structs which indicates who will have access to the created KVDB
     * @param managers array of UserWithPubKey structs which indicates who will have access (and management rights) to the created KVDB
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param policies KVDB's policies
     * @return ID of the created KVDB
     */
    std::string createKvdb(const std::string& contextId, 
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers, 
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta, 
        const std::optional<core::ContainerPolicy>& policies = std::nullopt
    );

    /**
     * Updates an existing KVDB.
     *
     * @param kvdbId ID of the KVDB to update
     * @param users array of UserWithPubKey structs which indicates who will have access to the created KVDB
     * @param managers array of UserWithPubKey structs which indicates who will have access (and management rights) to the created KVDB
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param version current version of the updated KVDB
     * @param force force update (without checking version)
     * @param forceGenerateNewKey force to regenerate a key for the KVDB
     * @param policies KVDB's policies
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
     * Deletes a KVDB by given KVDB ID.
     *
     * @param kvdbId ID of the KVDB to delete
     */
    void deleteKvdb(const std::string& kvdbId);

    /**
     * Gets a KVDB by given KVDB ID.
     *
     * @param kvdbId ID of KVDB to get
     * @return struct containing info about the KVDB
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
     * Gets a KVDB entry by given KVDB entry key and KVDB ID.
     *
     * @param kvdbId KVDB ID of the KVDB entry to get
     * @param key key of the KVDB entry to get
     * @return struct containing the KVDB entry
     */    
    KvdbEntry getEntry(const std::string& kvdbId, const std::string& key);

    /**
     * Check whether the KVDB entry exists.
     *
     * @param kvdbId KVDB ID of the KVDB entry to check
     * @param key key of the KVDB entry to check
     * @returns 'true' if the KVDB has an entry with given key, 'false' otherwise
     */   
    bool hasEntry(const std::string& kvdbId, const std::string& key);

    /**
     * Gets a list of KVDB entries keys from a KVDB.
     *
     * @param kvdbId ID of the KVDB to list KVDB entries from
     * @param pagingQuery with list query parameters
     * @return struct containing a list of KVDB entries
     */    
    core::PagingList<std::string> listEntriesKeys(const std::string& kvdbId, const core::PagingQuery& pagingQuery);

    /**
     * Gets a list of KVDB entries from a KVDB.
     *
     * @param kvdbId ID of the KVDB to list KVDB entries from
     * @param pagingQuery  with list query parameters
     * @return struct containing a list of KVDB entries
     */    
    core::PagingList<KvdbEntry> listEntries(const std::string& kvdbId, const core::PagingQuery& pagingQuery);

    /**
     * Sets a KVDB entry in the given KVDB.
     * @param kvdbId ID of the KVDB to set the entry to
     * @param key KVDB entry key
     * @param publicMeta public KVDB entry metadata
     * @param privateMeta private KVDB entry metadata
     * @param data content of the KVDB entry
     * @return ID of the new KVDB entry
     */    
    void setEntry(const std::string& kvdbId, const std::string& key, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data, int64_t version = 0);
    
    /**
     * Deletes a KVDB entry by given KVDB entry ID.
     *
     * @param kvdbId KVDB ID of the KVDB entry to delete
     * @param key key of the KVDB entry to delete
     */    
    void deleteEntry(const std::string& kvdbId, const std::string& key);

    /**
     * Deletes KVDB entries by given KVDB IDs and the list of entry keys.
     *
     * @param kvdbId ID of the KVDB database to delete from
     * @param keys vector of the keys of the KVDB entries to delete
     * @return map with the statuses of deletion for every key
     */    
    std::map<std::string, bool> deleteEntries(const std::string& kvdbId, const std::vector<std::string>& keys);

    /**
     * Subscribe for the KVDB events on the given subscription query.
     * 
     * @param subscriptionQueries list of queries
     * @return list of subscriptionIds in maching order to subscriptionQueries
     */
    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);

    /**
     * Unsubscribe from events for the given subscriptionId.
     * @param subscriptionIds list of subscriptionId
     */
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);

    /**
     * Generate subscription Query for the KVDB events.
     * @param eventType type of event which you listen for
     * @param selectorType scope on which you listen for events  
     * @param selectorId ID of the selector
     */
    std::string buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId);

    /**
     * Generate subscription Query for the KVDB events for single KvdbEntry.
     * @param eventType type of event which you listen for
     * @param kvdbId Id of Kvdb 
     * @param kvdbEntryId Key of Kvdb Entry
     */
    std::string buildSubscriptionQueryForSelectedEntry(EventType eventType, const std::string& kvdbId, const std::string& kvdbEntryKey);

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
