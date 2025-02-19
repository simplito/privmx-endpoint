#ifndef _PRIVMXLIB_ENDPOINT_CORE_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_TYPES_HPP_

#include <optional>
#include <string>
#include <vector>

namespace privmx {
namespace endpoint {
namespace core {

template<typename T>

/**
* Contains results of listing methods.
*/
 struct PagingList {
    /**
     * total items available to get
     */
    int64_t totalAvailable;

    /**
     * list of items read during single method call
     */
    std::vector<T> readItems;
};

/**
 * Contains query parameters for methods returning lists (PagingList).
 */
struct PagingQuery {
    /**
     * number of elements to skip from result
     */
    int64_t skip;

    /**
     * limit of elements to return for query
     */
    int64_t limit;

    /**
     * order of elements in result ("asc" for ascending, "desc" for descending)
     */
    std::string sortOrder;

    /**
     * ID of the element from which query results should start
     */
    std::optional<std::string> lastId;

    /**
     * extra query parameters in serialized JSON  
     */
    std::optional<std::string> queryAsJson;
};

/**
 * Contains base Context information.
 */
struct Context {
    /**
     * ID of the user requesting information
     */
    std::string userId;

    /**
     * ID of the Context
     */
    std::string contextId;
};

/**
 * Contains ID of a user and the corresponding public key.
 */
struct UserWithPubKey {
    /**
     * ID of the user
     */
    std::string userId;

    /**
     * user's public key
     */
    std::string pubKey;
};

/**
 * Contains Infomation about user
 */
struct UserInfo {
    /**
     * User publicKey and usetId
     */
    UserWithPubKey user;

    /**
     *  is user connected to bridge
     */
    bool isActive;
};


/**
 * Contains container's policies.
 */
struct ContainerPolicyWithoutItem {
    /** 
     * Determine who can get a container 
     */
    std::optional<std::string> get;
    /** 
     * Determine who can update a container 
     */
    std::optional<std::string> update;
    /** 
     * Determine who can delete a container 
     */
    std::optional<std::string> delete_;
    /** 
     * Determine who can update policy 
     */
    std::optional<std::string> updatePolicy;
    /** 
     * Determine whether the updater can be removed from the list of managers 
     */
    std::optional<std::string> updaterCanBeRemovedFromManagers;
    /** 
     * Determine whether the owner can be removed from the list of managers 
     */
    std::optional<std::string> ownerCanBeRemovedFromManagers;
};

/**
 * Contains container items policies.
 */
struct ItemPolicy {
    /** 
     * Determine who can get an item
     */
    std::optional<std::string> get;
    /** 
     * Determine who can list items created by me 
     */
    std::optional<std::string> listMy;
    /** 
     * Determine who can list all items
     */
    std::optional<std::string> listAll;
    /** 
     * Determine who can create an item 
     */
    std::optional<std::string> create;
    /**
     *  Determine who can update an item
     */
    std::optional<std::string> update;
    /** 
     * Determine who can delete an item 
     */
    std::optional<std::string> delete_;    
};

/**
 * Contains container and its items policies.
 */
struct ContainerPolicy : public ContainerPolicyWithoutItem {
    /** 
     * Policy for container's items
     */
    std::optional<ItemPolicy> item;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_TYPES_HPP_
