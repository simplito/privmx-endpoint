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
 * 'GroupApi' is a class representing Endpoint's API for user groups.
 */
class GroupApi : public privmx::endpoint::core::ExtendedPointer<GroupApiImpl>  {
public:
    /**
     * Creates an instance of 'GroupApi'.
     * 
     * @param connection instance of 'Connection'
     * 
     * @return GroupApi object
     */
    static GroupApi create(core::Connection& connetion);

    /**
     * //doc-gen:ignore
     */
    GroupApi();
    GroupApi(const GroupApi& obj);
    GroupApi& operator=(const GroupApi& obj);
    GroupApi(GroupApi&& obj);
    ~GroupApi();

    /**
     * Creates a new group in given Context.
     *
     * @param contextId ID of the Context to create the group in
     * @param users vector of UserWithPubKey structs which indicates who will have access to the created group and its resources
     * @param managers vector of UserWithPubKey structs which indicates who will have access (and management rights) to
     * the created group and its resources
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @return ID of the created group
     */
    std::string createGroup(const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
                             const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, 
                             const core::Buffer& privateMeta);
    
    /**
     * Updates an existing group.
     *
     * @param groupId ID of the group to update
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param version current version of the group
     * @param force force update (without checking version)
     */
    void updateGroup(const std::string& groupId, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                      const int64_t version, const bool force);

    /**
     * Modifies the group's membership by adding and removing specific users.
     * 
     * This is a partial update (delta). Users provided in usersToAddOrUpdate or managersToAddOrUpdate will be 
     * granted access, while users in usersToRemove or managersToRemove will have their access revoked.
     * Existing members not mentioned in either list remain unaffected.
     * 
     * @param groupId ID of the group to be modified
     * @param usersToAddOrUpdate list of users as UserWithPubKey to be added or, if already present, updated within the group
     * @param usersToRemove list of users as ID to be removed from the group, ignored if the user is not a user member
     * @param managersToAddOrUpdate list of managers as UserWithPubKey to be added or, if already present, updated within the group
     * @param managersToRemove list of managers as ID to be removed from the group, ignored if the user is not a manager member
     */
    void modifyGroupMembers(const std::string& groupId,
        const std::vector<core::UserWithPubKey>& usersToAddOrUpdate, const std::vector<std::string>& usersToRemove,
        const std::vector<core::UserWithPubKey>& managersToAddOrUpdate, const std::vector<std::string>& managersToRemove);

    /**
     * Deletes a group by given group ID.
     *
     * @param groupId ID of the group to delete
     */
    void deleteGroup(const std::string& groupId);

    /**
     * Gets a group by given group ID.
     *
     * @param groupId ID of group to get
     * @return `Group` struct containing info about the group
     */
    Group getGroup(const std::string& groupId);

    /**
     * Gets a list of group in given Context.
     *
     * @param contextId ID of the Context to get the groups from
     * @param pagingQuery struct with list query parameters
     * @return struct containing a list of groups
     */
    core::PagingList<Group> listGroups(const std::string& contextId, const core::PagingQuery& pagingQuery);

private:
    GroupApi(const std::shared_ptr<GroupApiImpl>& impl);
};

}  // namespace group
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPI_HPP_
