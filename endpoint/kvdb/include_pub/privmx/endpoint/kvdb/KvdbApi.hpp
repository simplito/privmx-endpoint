#ifndef _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPI_HPP_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/kvdb/Types.hpp"
#include <privmx/endpoint/core/ExtendedPointer.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>

namespace privmx {
namespace endpoint {
namespace kvdb {

class KvdbApiImpl;

/**
 * 'KvdbApi' is a class representing Endpoint's API for Kvdbs and their messages.
 */
class KvdbApi : public privmx::endpoint::core::ExtendedPointer<KvdbApiImpl> {
public:
    /**
     * Creates an instance of 'KvdbApi'.
     *
     * @param connection instance of 'Connection'
     * @param groupApi instance of 'GroupApi', required to read and write KVDBs granted to groups
     *
     * @return KvdbApi object
     */
    static KvdbApi create(
        core::Connection& connection,
        const std::optional<group::GroupApi>& groupApi = std::nullopt
    );

    /**
     * //doc-gen:ignore
     */
    KvdbApi();
    KvdbApi(const KvdbApi& obj);
    KvdbApi& operator=(const KvdbApi& obj);
    KvdbApi(KvdbApi&& obj);
    ~KvdbApi();

    /**
     * Creates a new KVDB in given Context.
     *
     * @param contextId ID of the Context to create the KVDB in
     * @param users array of UserWithPubKey structs which indicates who will have access to the created KVDB
     * @param managers array of UserWithPubKey structs which indicates who will have access (and management rights) to the created KVDB
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param policies KVDB's policies
     * @param groups groups granted access to the KVDB, with their verified epoch public keys
     * @return ID of the created KVDB
     */
    std::string createKvdb(
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies = std::nullopt,
        const std::vector<core::GroupGrantWithKey>& groups = {}
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
     * @param groups groups granted access to the KVDB, with their verified epoch public keys; the list is
     * authoritative — an empty list revokes every group grant the KVDB had
     */
    void updateKvdb(
        const std::string& kvdbId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const int64_t version,
        const bool force,
        const bool forceGenerateNewKey,
        const std::optional<core::ContainerPolicy>& policies = std::nullopt,
        const std::vector<core::GroupGrantWithKey>& groups = {}
    );

    /**
     * Re-encrypts the KVDB key for all current members without changing data, membership, or policy.
     * Unlike updateKvdb, this can be called by any KVDB member (not just managers) when the
     * default rotateKeys policy of "user" is in effect.
     *
     * The KVDB's key is re-wrapped to every one of its grantee groups at that group's current epoch, whether or
     * not the caller belongs to the group and whether or not it names the group in `groups`: the grantee list comes
     * from the KVDB itself, and any epoch public key missing from `groups` is read from the Bridge.
     *
     * @param kvdbId ID of the KVDB to re-key
     * @param users current KVDB users with their public keys
     * @param managers current KVDB managers with their public keys
     * @param version current KVDB version (optimistic lock guard)
     * @param force skip the version check when true
     * @param groups epoch public keys of grantee groups the caller has verified itself; optional, and groups the
     * KVDB does not grant are ignored — a re-key changes no grants
     */
    void rotateKvdbKeys(
        const std::string& kvdbId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const int64_t version,
        const bool force,
        const std::vector<core::GroupGrantWithKey>& groups = {}
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
     */
    void setEntry(
        const std::string& kvdbId,
        const std::string& key,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const core::Buffer& data,
        int64_t version = 0
    );

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
    std::string buildSubscriptionQuery(
        EventType eventType,
        EventSelectorType selectorType,
        const std::string& selectorId
    );

    /**
     * Generate subscription Query for the KVDB events for single KvdbEntry.
     * @param eventType type of event which you listen for
     * @param kvdbId Id of Kvdb 
     * @param kvdbEntryId Key of Kvdb Entry
     */
    std::string buildSubscriptionQueryForSelectedEntry(
        EventType eventType,
        const std::string& kvdbId,
        const std::string& kvdbEntryKey
    );

private:
    KvdbApi(const std::shared_ptr<KvdbApiImpl>& impl);
};

} // namespace kvdb
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPI_HPP_
