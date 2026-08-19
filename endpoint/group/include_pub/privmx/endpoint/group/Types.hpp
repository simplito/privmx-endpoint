#ifndef _PRIVMXLIB_ENDPOINT_GROUP_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_TYPES_HPP_

#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/Types.hpp"

namespace privmx {
namespace endpoint {
namespace group {

/**
 * Holds all available information about a Group.
 */
struct Group {
    /**
     * ID of the Context
     */
    std::string contextId;

    /**
     * ID of the Group
     */
    std::string groupId;

    /**
     * Group identity public key (base58-DER encoded)
     */
    std::string groupPubKey;

    /**
     * Group creation timestamp
     */
    int64_t createDate;

    /**
     * ID of user who created the Group
     */
    std::string creator;

    /**
     * Group last modification timestamp
     */
    int64_t lastModificationDate;

    /**
     * ID of the user who last modified the Group
     */
    std::string lastModifier;

    /**
     * list of users (their IDs) with access to the Group
     */
    std::vector<std::string> users;

    /**
     * list of users (their IDs) with management rights
     */
    std::vector<std::string> managers;

    /**
     * version number (= number of history entries; changes on updates)
     */
    int64_t version;

    /**
     * Group's public metadata
     */
    core::Buffer publicMeta;

    /**
     * Group's private metadata
     */
    core::Buffer privateMeta;

    /**
     * Group's policies
     */
    core::ContainerPolicy policy;

    /**
     * status code of retrieval and verification of the Group (0 = success)
     */
    int64_t statusCode;

    /**
     * Version of the Group data structure and how it is encoded/encrypted
     */
    int64_t schemaVersion;

    /**
     * Optional type tag
     */
    std::optional<std::string> type;

    /**
     * Epoch counter for the group identity keypair. Increments by 1 on each key rotation
     * triggered by a member removal. Matches the bridge's CAS field. 0 for Phase-1 groups
     * whose bridge does not yet emit this field.
     */
    int64_t keyVersion;
};

/**
 * Holds the information about a Group that a listing serves: identity, roster, epoch and policies.
 *
 * A listing deliberately carries no per-Group state — the Bridge does not send the encrypted data, the
 * key entries or the history for a page of Groups, because those grow with membership and with every
 * change. So there is no `publicMeta`/`privateMeta` here (nothing to decrypt from), no `schemaVersion`
 * (it is recorded inside the encrypted data), and no `statusCode` (nothing was decrypted or verified,
 * so there is no status to report). Call `getGroup` for any of those.
 */
struct GroupSummary {
    /**
     * ID of the Context
     */
    std::string contextId;

    /**
     * ID of the Group
     */
    std::string groupId;

    /**
     * Group identity public key (base58-DER encoded)
     */
    std::string groupPubKey;

    /**
     * Group creation timestamp
     */
    int64_t createDate;

    /**
     * ID of user who created the Group
     */
    std::string creator;

    /**
     * Group last modification timestamp
     */
    int64_t lastModificationDate;

    /**
     * ID of the user who last modified the Group
     */
    std::string lastModifier;

    /**
     * list of users (their IDs) with access to the Group
     */
    std::vector<std::string> users;

    /**
     * list of users (their IDs) with management rights
     */
    std::vector<std::string> managers;

    /**
     * version number (= number of history entries; changes on updates)
     */
    int64_t version;

    /**
     * Group's policies
     */
    core::ContainerPolicy policy;

    /**
     * Optional type tag
     */
    std::optional<std::string> type;

    /**
     * Epoch counter for the group identity keypair. Increments by 1 on each key rotation
     * triggered by a member removal. Matches the bridge's CAS field. 0 for Phase-1 groups
     * whose bridge does not yet emit this field.
     */
    int64_t keyVersion;
};

enum EventType : int64_t {
    GROUP_CREATE = 0,
    GROUP_UPDATE = 1,
    GROUP_DELETE = 2,
};

enum EventSelectorType : int64_t {
    CONTEXT_ID = 0,
    GROUP_ID = 1,
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_TYPES_HPP_
