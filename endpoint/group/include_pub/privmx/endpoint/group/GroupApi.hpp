#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPI_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/group/Types.hpp"
#include <privmx/endpoint/core/ExtendedPointer.hpp>

namespace privmx {
namespace endpoint {
namespace group {

class GroupApiImpl;

/**
 * 'GroupApi' is a class representing Endpoint's API for Groups.
 */
class GroupApi : public privmx::endpoint::core::ExtendedPointer<GroupApiImpl> {
public:
    /**
     * Creates an instance of 'GroupApi'.
     *
     * @param connection instance of 'Connection'
     * @return GroupApi object
     */
    static GroupApi create(core::Connection& connection);

    /**
     * //doc-gen:ignore
     */
    GroupApi();
    GroupApi(const GroupApi& obj);
    GroupApi& operator=(const GroupApi& obj);
    GroupApi(GroupApi&& obj);
    ~GroupApi();

    /**
     * Creates a new Group whose key distribution is backed by a hidden key tree.
     *
     * Removing a member is proportional to the logarithm of the group size instead of to the group size, and
     * adding one does not advance the group's key epoch, so no container the group can read has to be re-keyed.
     *
     * The group's own metadata key is wrapped once to the group itself rather than once per member, which is what
     * keeps a removal off the linear path entirely.
     *
     * @param contextId ID of the Context to create the Group in
     * @param users vector of UserWithPubKey structs which indicates who will have access to the created Group
     * @param managers vector of UserWithPubKey structs which indicates who will have access (and management
     * rights) to the created Group
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param policies Group's policies
     * @return ID of the created Group
     */
    std::string createGroup(
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies = std::nullopt
    );

    /**
     * Adds one member to a tree-backed Group, without advancing its key epoch.
     *
     * Costs one wrap for the new member plus one metadata key entry. Because the epoch does not move, every
     * container the Group can read stays valid and nobody else re-keys anything.
     *
     * @param groupId ID of the Group
     * @param newMember the member to add, with their public key
     * @param asManager whether the new member joins as a manager
     * @param users full member list *after* the addition
     * @param managers full manager list *after* the addition
     * @param publicMeta public (unencrypted) metadata to store with this change
     * @param privateMeta private (encrypted) metadata to store with this change
     */
    void addGroupMember(
        const std::string& groupId,
        const core::UserWithPubKey& newMember,
        bool asManager,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta
    );

    /**
     * Removes one member from a tree-backed Group and advances its key epoch.
     *
     * Does everything a removal requires in one call: blanks the member's leaf, replaces every key on the path
     * from it to the root, mints a new epoch key, publishes the archive rungs that keep older epochs reachable,
     * and re-wraps the Group's metadata key once. Containers the Group can read must be re-keyed afterwards; the
     * bridge refuses new content written under the superseded epoch until they are.
     *
     * @param groupId ID of the Group
     * @param userId ID of the member to remove
     * @param users member list that *remains*, without the removed member
     * @param managers manager list that remains
     * @param publicMeta public (unencrypted) metadata to store with this change
     * @param privateMeta private (encrypted) metadata to store with this change
     */
    void removeGroupMember(
        const std::string& groupId,
        const std::string& userId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta
    );

    /**
     * Updates an existing Group's metadata.
     *
     * The membership is deliberately not updatable here: seating a member and re-keying their path is one
     * operation on the Group's key tree, so it goes through addGroupMember/removeGroupMember instead.
     *
     * @param groupId ID of the Group to update
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param version current version of the updated Group
     * @param force force update (without checking version)
     * @param forceGenerateNewKey force to regenerate a key for the Group
     * @param policies Group's policies
     */
    void updateGroup(
        const std::string& groupId,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const int64_t version,
        const bool force,
        const bool forceGenerateNewKey,
        const std::optional<core::ContainerPolicy>& policies = std::nullopt
    );

    /**
     * Deletes a Group by given Group ID.
     *
     * @param groupId ID of the Group to delete
     */
    void deleteGroup(const std::string& groupId);

    /**
     * Gets a Group by given Group ID.
     *
     * @param groupId ID of the Group to get
     * @return Group struct containing info about the Group
     */
    Group getGroup(const std::string& groupId);

    /**
     * Gets a list of Groups in given Context.
     *
     * The listing carries no per-Group metadata: a page holds identity, roster, epoch and policies only.
     * Call `getGroup` for a Group's `publicMeta`/`privateMeta` and for its verified status.
     *
     * @param contextId ID of the Context to get the Groups from
     * @param pagingQuery struct with list query parameters
     * @return struct containing a list of Group summaries
     */
    core::PagingList<GroupSummary> listGroups(const std::string& contextId, const core::PagingQuery& pagingQuery);

    /**
     * Subscribe for the Group events on the given subscription query.
     *
     * @param subscriptionQueries list of queries
     * @return list of subscriptionIds in matching order to subscriptionQueries
     */
    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);

    /**
     * Unsubscribe from events for the given subscriptionIds.
     *
     * @param subscriptionIds list of subscriptionId
     */
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);

    /**
     * Generate subscription Query for the Group events.
     *
     * @param eventType type of event which you listen for
     * @param selectorType scope on which you listen for events
     * @param selectorId ID of the selector
     */
    std::string buildSubscriptionQuery(
        EventType eventType,
        EventSelectorType selectorType,
        const std::string& selectorId
    );

private:
    GroupApi(const std::shared_ptr<GroupApiImpl>& impl);
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPI_HPP_
