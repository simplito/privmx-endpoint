#ifndef _PRIVMXLIB_ENDPOINT_GROUP_EVENTS_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_EVENTS_HPP_

#include "privmx/endpoint/core/Events.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/group/Types.hpp"

namespace privmx {
namespace endpoint {
namespace group {

struct GroupDeletedEventData {

    /**
     * Group ID
     */
    std::string groupId;

    /**
     * Context ID
     */
    std::string contextId;
};

/**
 * Holds what changed about a Group, and nothing that grows with it.
 *
 * A Group event no longer carries the Group: the state was serialized once per recipient, so a Group of a
 * thousand members shipped its tree and history a thousand times for one membership change. The four counters
 * are enough to decide whether the change matters — and which plane moved; call `getGroup` when it does.
 */
struct GroupChangedEventData {

    /**
     * Group ID
     */
    std::string groupId;

    /**
     * Context ID
     */
    std::string contextId;

    /**
     * Public-metadata version after the change. Moves only on `updateGroupPublicMeta`.
     */
    int64_t publicMetaVersion;

    /**
     * Private-metadata version after the change. Moves only on `updateGroupPrivateMeta`.
     */
    int64_t privateMetaVersion;

    /**
     * Roster version after the change. Moves only on a membership change.
     */
    int64_t rosterVersion;

    /**
     * Group key epoch after the change
     */
    int64_t keyVersion;

    /**
     * Which operation changed the Group: "created", "publicMetaUpdated", "privateMetaUpdated",
     * "policyUpdated", "keyRotated", "memberAdded", "memberRemoved", "eraCut" or "archivePruned"
     */
    std::string changeKind;
};

/**
 * Holds a custom notification that another member of the Group sent.
 *
 * The payload arrives sealed with the Group's own key and is opened here, so nothing about the notification's
 * cost depends on how many members the Group has — the sender sealed it once and the bridge relayed it once.
 */
struct GroupCustomEventData {

    /**
     * Group ID
     */
    std::string groupId;

    /**
     * Name of the channel the notification was sent on
     */
    std::string channelName;

    /**
     * ID of the sender, as the bridge reported it. NOT authenticated — see `authorPubKey`.
     */
    std::string userId;

    /**
     * Public key of the sender (base58-DER encoded), whose signature over the payload has been verified.
     *
     * This is the field that attests to the author. EMPTY when `statusCode` is non-zero.
     */
    std::string authorPubKey;

    /**
     * Decrypted payload. EMPTY when `statusCode` is non-zero.
     */
    core::Buffer payload;

    /**
     * 0 when the payload was opened. Otherwise the error that stopped it — the Group's key for this
     * notification could not be resolved, or the payload did not verify.
     */
    int64_t statusCode;
};

/**
 * Holds data of event that arrives when a Group is created.
 */
struct GroupCreatedEvent : public core::Event {

    /**
     * Event constructor
     */
    GroupCreatedEvent() : core::Event("groupCreated") {}

    /**
     * Get Event as JSON string
     *
     * @return JSON string
     */
    std::string toJSON() const override;

    /**
     * //doc-gen:ignore
     */
    std::shared_ptr<core::SerializedEvent> serialize() const override;

    /**
     * what changed about the Group
     */
    GroupChangedEventData data;
};

/**
 * Holds data of event that arrives when a Group is updated.
 */
struct GroupUpdatedEvent : public core::Event {

    /**
     * Event constructor
     */
    GroupUpdatedEvent() : core::Event("groupUpdated") {}

    /**
     * Get Event as JSON string
     *
     * @return JSON string
     */
    std::string toJSON() const override;

    /**
     * //doc-gen:ignore
     */
    std::shared_ptr<core::SerializedEvent> serialize() const override;

    /**
     * what changed about the Group
     */
    GroupChangedEventData data;
};

/**
 * Holds data of event that arrives when a Group is deleted.
 */
struct GroupDeletedEvent : public core::Event {

    /**
     * Event constructor
     */
    GroupDeletedEvent() : core::Event("groupDeleted") {}

    /**
     * Get Event as JSON string
     *
     * @return JSON string
     */
    std::string toJSON() const override;

    /**
     * //doc-gen:ignore
     */
    std::shared_ptr<core::SerializedEvent> serialize() const override;

    /**
     * event data
     */
    GroupDeletedEventData data;
};

/**
 * Holds data of event that arrives when a member of a Group sends a custom notification.
 */
struct GroupCustomEvent : public core::Event {

    /**
     * Event constructor
     */
    GroupCustomEvent() : core::Event("groupCustom") {}

    /**
     * Get Event as JSON string
     *
     * @return JSON string
     */
    std::string toJSON() const override;

    /**
     * //doc-gen:ignore
     */
    std::shared_ptr<core::SerializedEvent> serialize() const override;

    /**
     * the notification
     */
    GroupCustomEventData data;
};

/**
 * 'Events' provides helper methods for group events management.
 */
class Events {
public:
    /**
     * Checks whether event held in the 'EventHolder' is a 'GroupCreatedEvent'
     */
    static bool isGroupCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as a 'GroupCreatedEvent'
     */
    static GroupCreatedEvent extractGroupCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is a 'GroupUpdatedEvent'
     */
    static bool isGroupUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as a 'GroupUpdatedEvent'
     */
    static GroupUpdatedEvent extractGroupUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is a 'GroupDeletedEvent'
     */
    static bool isGroupDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as a 'GroupDeletedEvent'
     */
    static GroupDeletedEvent extractGroupDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is a 'GroupCustomEvent'
     */
    static bool isGroupCustomEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as a 'GroupCustomEvent'
     */
    static GroupCustomEvent extractGroupCustomEvent(const core::EventHolder& eventHolder);
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_EVENTS_HPP_
