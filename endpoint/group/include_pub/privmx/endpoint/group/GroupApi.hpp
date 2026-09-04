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
     * Adds members to a tree-backed Group, without advancing its key epoch.
     *
     * Not `k` separate additions bundled: the newcomers' paths overlap, so this re-keys their union once and
     * lands under a single compare-and-swap. Because the epoch does not move, every container the Group can read
     * stays valid and nobody else re-keys anything.
     *
     * Incremental: only the newcomers are named. The resulting roster is derived from the Group's own verified
     * history, and its metadata carries through untouched — seating a member is not a metadata edit, and
     * `updateGroup` is where that happens.
     *
     * @param groupId ID of the Group
     * @param newMembers the members to add, each with their public key and the role they take
     */
    void addGroupMembers(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers);

    /**
     * Removes several members at once, advancing the key epoch **once**.
     *
     * This is why the batch exists. Removing them one at a time advances the epoch per member, so every container
     * the Group can read goes stale `k` times and the Group's rotation budget is charged `k` times; a batch costs
     * one epoch, one set of archive rungs and one metadata re-wrap however many members leave.
     *
     * Incremental: only the leavers are named, and the roster that remains is derived from the Group's own
     * verified history. Metadata carries through untouched.
     *
     * @param groupId ID of the Group
     * @param userIds IDs of the members to remove
     */
    void removeGroupMembers(const std::string& groupId, const std::vector<std::string>& userIds);

    /**
     * Updates an existing Group's metadata.
     *
     * The membership is deliberately not updatable here: seating a member and re-keying their path is one
     * operation on the Group's key tree, so it goes through addGroupMembers/removeGroupMembers instead.
     *
     * There is no way to skip the version check. A Group's entry commits a tag over the version it lands at, so
     * an update computed against a head that has since moved cannot produce a tag any reader will accept — the
     * version pin is what keeps such an update from landing at all. A caller who loses the check has to re-read
     * the Group and build the update again.
     *
     * @param groupId ID of the Group to update
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param version current version of the updated Group
     * @param policies Group's policies
     */
    void updateGroup(
        const std::string& groupId,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const int64_t version,
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
