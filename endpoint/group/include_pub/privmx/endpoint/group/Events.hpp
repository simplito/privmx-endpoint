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
 * thousand members shipped its tree and history a thousand times for one membership change. `version` and
 * `keyVersion` are enough to decide whether the change matters; call `getGroup` when it does.
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
     * Group version after the change (= number of history entries)
     */
    int64_t version;

    /**
     * Group key epoch after the change
     */
    int64_t keyVersion;

    /**
     * Which operation changed the Group: "created", "updated", "keyRotated", "memberAdded", "memberRemoved",
     * "eraCut" or "archivePruned"
     */
    std::string changeKind;
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
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_EVENTS_HPP_
