/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPCLIENT_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPCLIENT_HPP_

#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/group/GroupApi.hpp"
#include "privmx/endpoint/group/Types.hpp"

namespace privmx {
namespace endpoint {
namespace group {

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// GroupClient - high level, by subject
//
// Everything here is built on the public methods of GroupApi and adds no cryptography. A Group is named by the
// entity of the application it serves (its subject: {"contact", "chat", <chatId>}) instead of by an ID read from
// a server, and every value is bound to `subject + place`.
// ════════════════════════════════════════════════════════════════════════════════════════════════════

/** A file being encrypted. The size need not be known; the envelope is made, and the content signed, in finish(). */
class GroupFileWriter {
public:
    GroupFileWriter() = default;
    GroupFileWriter(GroupApi api, FileHandle handle) : _api(std::move(api)), _handle(handle) {}
    /** @return the ciphertext of `plainChunk`, whole */
    core::Buffer encryptChunk(const core::Buffer& plainChunk);
    /** @return the file envelope; keep it next to the ciphertext */
    core::Buffer finish();

private:
    GroupApi _api;
    FileHandle _handle = 0;
};

/** A file being decrypted. Every chunk is checked against the digest the writer put in the envelope. */
class GroupFileReader {
public:
    GroupFileReader() = default;
    GroupFileReader(GroupApi api, FileHandle handle) : _api(std::move(api)), _handle(handle) {}
    core::Buffer decryptChunk(const core::Buffer& cipherChunk);
    /** Which ciphertext bytes hold plaintext bytes [from, to): for an HTTP Range request. */
    CipherRange getCipherRange(int64_t from, int64_t to);
    /** @return where in the ciphertext to continue reading from */
    int64_t seek(int64_t position);
    DecryptedFileInfo finish();

private:
    GroupApi _api;
    FileHandle _handle = 0;
};

/** A sequence being written. See "Sequences" in GroupApi for what a reader can rely on, and when. */
class GroupSequenceWriter {
public:
    GroupSequenceWriter() = default;
    GroupSequenceWriter(GroupApi api, SequenceHandle handle) : _api(std::move(api)), _handle(handle) {}
    /** The signed header. Send or store it before the items. */
    core::Buffer getHeader();
    SequenceAppendResult append(const core::Buffer& data);
    core::Buffer checkpoint();
    /** A final checkpoint that also says nothing follows. */
    core::Buffer finish();

private:
    GroupApi _api;
    SequenceHandle _handle = 0;
};

class GroupSequenceReader {
public:
    GroupSequenceReader() = default;
    GroupSequenceReader(GroupApi api, SequenceHandle handle) : _api(std::move(api)), _handle(handle) {}
    SequenceItem read(const core::Buffer& item);
    SequenceMarkInfo verify(const core::Buffer& mark);
    /** For a sequence read from a Space: who wrote it, and how they had access. */
    SpaceOrigin getSpaceOrigin();
    void close();

private:
    GroupApi _api;
    SequenceHandle _handle = 0;
};

/**
 * One opened Group. A thin object: it holds the Group's ID and its subject, and forwards to GroupApi with
 * `location = subject + place`. It is a name, not a snapshot: every call works on the Group's current verified
 * state. (`Group` is the data GroupApi::getGroup returns; this is the handle.)
 *
 * An unbound Group (GroupClient::createUnboundGroup, openUnboundGroup) has an empty subject: every `place`
 * below is then a full location, or GroupApi::noLocation().
 */
class GroupHandle {
public:
    GroupHandle() = default;
    GroupHandle(GroupApi api, std::string contextId, std::string groupId, Path subject)
        : _api(std::move(api)), _contextId(std::move(contextId)), _groupId(std::move(groupId)),
          _subject(std::move(subject)) {}

    /** For passing to other modules (a container's grant list). Never read one back in from a server. */
    std::string getGroupId() const { return _groupId; }
    Path getSubject() const { return _subject; }
    Group getState();
    core::PagingList<GroupLogEntry> getLog(const core::PagingQuery& query);

    // ── Envelopes; `place` is the path under the subject, at least one segment ──
    /** A further recipient Group in `options.alsoFor` may be named by its subject. */
    core::Buffer encrypt(const Path& place, const core::Buffer& data, const EncryptOptions& options = {});
    DecryptedEnvelope decrypt(const Path& place, const core::Buffer& envelope, const DecryptOptions& options);
    /** As GroupApi::decryptMany; each item's `location` is a place under the subject. */
    std::vector<DecryptResult> decryptMany(const std::vector<DecryptItem>& items);
    /** Written to this Group, and signed, by someone who is not in it (GroupClient::openForWriting). */
    DecryptedOutsiderEnvelope decryptFromOutsider(
        const Path& place,
        const core::Buffer& envelope,
        const DecryptOptions& options
    );
    /** Written to this Group, unsigned (GroupOutsider::anonymous). */
    DecryptedAnonymousEnvelope decryptAnonymous(const Path& place, const core::Buffer& envelope);

    // ── Files ──
    GroupFileWriter beginFileEncryption(const Path& place, const EncryptOptions& options = {});
    GroupFileReader beginFileDecryption(const Path& place, const core::Buffer& envelope, const DecryptOptions& options);
    GroupFileReader beginFileDecryptionFromOutsider(
        const Path& place,
        const core::Buffer& envelope,
        const DecryptOptions& options
    );
    GroupFileReader beginAnonymousFileDecryption(const Path& place, const core::Buffer& envelope);

    // ── Sequences ──
    GroupSequenceWriter beginSequence(const Path& place, int64_t checkpointEvery = 64);
    GroupSequenceReader openSequence(
        const Path& place,
        const core::Buffer& header,
        const DecryptOptions& options,
        const std::optional<core::Buffer>& resumeFrom = std::nullopt
    );

    // ── Membership ──
    void addMembers(const std::vector<GroupMemberToAdd>& members);
    int64_t removeMembers(const std::vector<std::string>& userIds);
    int64_t reseatMembers(const std::vector<std::string>& userIds);
    void setRoles(const std::vector<GroupRoleChange>& changes);
    int64_t rotateKey();
    void updatePublicMeta(const core::Buffer& meta, int64_t version);
    void updatePrivateMeta(const core::Buffer& meta, int64_t version);
    void updateRules(const GroupRulesUpdate& rules);
    void setVisibility(const std::string& visibleTo);
    void deleteGroup();

    // ── Events ──
    void sendCustomEvent(
        const std::string& channelName,
        const core::Buffer& eventData,
        const std::vector<std::string>& users = {}
    );
    /** Queries for GroupApi::subscribeFor. */
    std::string buildSubscriptionQuery(EventType eventType);
    std::string buildCustomEventSubscriptionQuery(const std::string& channelName);

private:
    Path at(const Path& place) const;
    GroupApi _api;
    std::string _contextId;
    std::string _groupId;
    Path _subject;
};

/**
 * A Group as seen by someone who is not in it: they can write to it, and read nothing - not even what they
 * wrote. It writes exactly as GroupHandle does: encrypt, and files in chunks.
 *
 * - GroupClient::openForWriting: for an account that is not in the Group. Envelopes are signed by it; the Group
 *   learns who wrote them.
 * - GroupOutsider::anonymous: from a key the Group published. No request to the Bridge. Envelopes are unsigned:
 *   the Group learns nothing about the writer. `alsoFor` is not available.
 *
 * The Group reads the first with decryptFromOutsider and the second with decryptAnonymous, never with decrypt.
 */
class GroupOutsider {
public:
    /** @param subject the subject of the Group the key belongs to: the readers open values at subject + place */
    static GroupOutsider anonymous(GroupApi api, const GroupPublicKey& key, const Path& subject);
    GroupOutsider() = default;

    core::Buffer encrypt(const Path& place, const core::Buffer& data, const EncryptOptions& options = {});
    GroupFileWriter beginFileEncryption(const Path& place, const EncryptOptions& options = {});

private:
    friend class GroupClient;
    Path at(const Path& place) const;
    GroupApi _api;
    std::string _contextId; // empty for an anonymous writer
    std::string _groupId;
    std::string _groupPubKey; // an anonymous writer only
    Path _subject;
};

/**
 * One opened Space: one key for several Groups. See "Spaces" in GroupApi for what it is for, and for what a
 * stale key means. Forwards to GroupApi with `location = subject + place`; in an unbound Space the subject
 * is empty and a `place` is a full location, or GroupApi::noLocation().
 */
class Space {
public:
    Space() = default;
    Space(GroupApi api, std::string contextId, std::string spaceId, Path subject)
        : _api(std::move(api)), _contextId(std::move(contextId)), _spaceId(std::move(spaceId)),
          _subject(std::move(subject)) {}

    std::string getSpaceId() const { return _spaceId; }
    Path getSubject() const { return _subject; }
    SpaceState getState();

    core::Buffer encrypt(const Path& place, const core::Buffer& data);
    DecryptedSpaceEnvelope decrypt(const Path& place, const core::Buffer& envelope, const DecryptOptions& options);
    std::vector<SpaceDecryptResult> decryptMany(const std::vector<DecryptItem>& items);
    GroupFileWriter beginFileEncryption(const Path& place);
    GroupFileReader beginFileDecryption(const Path& place, const core::Buffer& envelope, const DecryptOptions& options);
    GroupSequenceWriter beginSequence(const Path& place, int64_t checkpointEvery = 64);
    GroupSequenceReader openSequence(
        const Path& place,
        const core::Buffer& header,
        const DecryptOptions& options,
        const std::optional<core::Buffer>& resumeFrom = std::nullopt
    );

    // ── Recipients: managers only. A recipient Group may be named by its subject. ──
    void addRecipients(const std::vector<SpaceRecipient>& recipients);
    int64_t removeRecipients(const std::vector<SpaceRecipientRef>& recipients);
    int64_t rotateKey();
    void updatePublicMeta(const core::Buffer& meta, int64_t version);
    void updatePrivateMeta(const core::Buffer& meta, int64_t version);
    void deleteSpace();

private:
    Path at(const Path& place) const;
    GroupApi _api;
    std::string _contextId;
    std::string _spaceId;
    Path _subject;
};

struct OpenGroupOptions {
    /**
     * The user who created the entity; needed unless the entity's identifier was made at random right before
     * createGroup. The Group's first, signed commit
     * names who created the Group; if it is someone else, openGroup throws GroupWrongCreatorException.
     * For a Space the creator is the Bridge's word: a Space has no signed history.
     */
    std::optional<std::string> createdBy;
};

/** One Group to open with openGroups. At most one of the optional fields is set; none means openGroup. */
struct OpenGroupItem {
    Path subject;
    /** As in openGroup with OpenGroupOptions::createdBy. */
    std::optional<std::string> createdBy;
    /** As in openFixedGroup: the users the Group must hold. */
    std::optional<std::vector<std::string>> fixedMembers;
    /** As in openPinnedGroup: the Group's own ID. */
    std::optional<std::string> pinnedGroupId;
};

struct OpenGroupResult {
    /** 0 on success; otherwise the code of the exception the single open would have thrown. */
    int64_t statusCode;
    GroupHandle group;
};

/**
 * The Groups of one Context, addressed by subject: {"contact", "chat", <chatId>}.
 *
 * groupId = GroupApi::deriveGroupId(contextId, GroupApi::encodePath(subject)). A reader computes it from the
 * entity it has open; nothing stored on a server takes part.
 *
 * Whoever knows a subject before its Group exists can create that Group first, with the right members and
 * themselves. The ways to create and open a Group differ in who can do that to you.
 *
 *   createGroup + openGroup                 A new entity whose identifier the caller makes at random right
 *       before createGroup (GroupApi::idFromString of a fresh UUID). Nobody knew it before the Group existed:
 *       neither another user nor the server can have created the Group first.
 *   createGroup + openGroup{createdBy}      The entity's identifier was known earlier (the server numbered it,
 *       an existing record); the Group may be created after it. Another user of the Context is caught:
 *       createGroup throws GroupAlreadyExistsException, and openGroup throws when the Group's creator is not
 *       the one expected. The application's own server is not caught if it also lies about the creator.
 *   (GroupApi) + openPinnedGroup            A Group that already exists under an ID of its own. The first time,
 *       the ID is taken on trust; from then on this device refuses any other Group for that subject.
 *   createFixedGroup + openFixedGroup       A subject the caller chose and a roster frozen for good; opening
 *       checks that the Group holds exactly the users the reader expects.
 *   createUnboundGroup + openUnboundGroup   No entity at all: Groups as before subjects. Another user cannot
 *       choose the ID; the application's server is NOT caught - the ID passed in is trusted.
 *
 * Never "open it, and create it if it is not there": that is how a Group someone else made under your
 * subject gets used.
 */
class GroupClient {
public:
    static GroupClient create(GroupApi groupApi, const std::string& contextId);
    GroupClient() = default;

    /**
     * Creates the Group of the entity `subject` names. Call it once per entity. Throws
     * GroupAlreadyExistsException when the subject has a Group: if the caller did not create it, someone else did.
     *
     * For a new entity, make its identifier at random right before the call (a fresh UUID through
     * GroupApi::idFromString); openGroup(subject) is then enough. For an identifier that was known before this
     * call, always open with OpenGroupOptions::createdBy.
     */
    GroupHandle createGroup(
        const Path& subject,
        const std::vector<GroupMemberToAdd>& members,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<GroupRules>& rules = std::nullopt,
        const std::string& visibleTo = "members"
    );
    /** Opens and verifies the Group of `subject`. Refuses a Group made by createFixedGroup. */
    GroupHandle openGroup(const Path& subject, const OpenGroupOptions& options = {});
    /**
     * Opens a Group that exists under an ID of its own (made through GroupApi) and ties it to `subject` on
     * this device. Throws GroupSubjectReboundException when the device knows the subject under another Group.
     * Envelopes are bound to subject + place, as with any other Group here.
     */
    GroupHandle openPinnedGroup(const Path& subject, const std::string& groupId);
    /**
     * Creates a Group under a subject the caller chose, with exactly `users` (all of them managers: nobody is
     * more than another), and a roster, roles and rules that can never change. Members can still rotate the key.
     * A member who lost their key cannot be reseated here: reseating is a removal's right, and there is none.
     */
    GroupHandle createFixedGroup(
        const Path& subject,
        const std::vector<core::UserWithPubKey>& users,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta
    );
    /** Opens a fixed Group; throws GroupMembershipMismatchException unless it holds exactly `userIds`. */
    GroupHandle openFixedGroup(const Path& subject, const std::vector<std::string>& userIds);
    /**
     * Opens many Groups with one request to the Bridge for their states (GroupApi::getGroups): a list of chats,
     * 1:1 chats among them. One result per item, in order; a Group that failed has a non-zero statusCode and an
     * unusable `group`.
     */
    std::vector<OpenGroupResult> openGroups(const std::vector<OpenGroupItem>& items);

    /**
     * Creates a Group that belongs to no entity, under a random ID (GroupHandle::getGroupId). The application
     * stores the ID. Nothing ties the Group to a record: whoever tells a device which ID to open chooses the
     * Group it encrypts for. Prefer openPinnedGroup when the Group has an entity after all.
     */
    GroupHandle createUnboundGroup(
        const std::vector<GroupMemberToAdd>& members,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<GroupRules>& rules = std::nullopt,
        const std::string& visibleTo = "members"
    );
    /** Opens a Group by its ID, as it is. No check of who created it or which entity it serves. */
    GroupHandle openUnboundGroup(const std::string& groupId);

    // ── Spaces ──
    /**
     * Creates the Space of an entity. As with createGroup: call it once, open with `createdBy`.
     * Throws GroupAlreadyExistsException when a Space under this subject exists.
     */
    Space createSpaceFor(
        const Path& subject,
        const std::vector<SpaceRecipient>& recipients,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta
    );
    /** Throws GroupWrongCreatorException when `createdBy` is set and someone else created the Space. */
    Space openSpace(const Path& subject, const OpenGroupOptions& options = {});
    /** A Space under a random ID (Space::getSpaceId), bound to no entity. The same trade as createUnboundGroup. */
    Space createUnboundSpace(
        const std::vector<SpaceRecipient>& recipients,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta
    );
    Space openUnboundSpace(const std::string& spaceId);

    /**
     * For an account that is not in the Group of `subject`: a writer that signs as the caller.
     * @param createdBy the user who created that Group. Anyone who knows a subject can make a Group under it
     * first, and a writer outside it would then write to theirs: throws GroupWrongCreatorException.
     */
    GroupOutsider openForWriting(const Path& subject, const std::string& createdBy);
    /**
     * The verified key of the Group of `subject`, to publish for writers with no account
     * (GroupOutsider::anonymous). A non-member may call it when the Group is visible to the Context.
     * @param createdBy as in openForWriting
     */
    GroupPublicKey getPublicKey(const Path& subject, const std::string& createdBy);

    /**
     * Reads what was written in another Group and shared with the caller through alsoFor
     * (GroupApi::decryptShared). The value sits at `authorSubject + place`, and must say it was written in
     * the Group of `authorSubject` (EnvelopeWrongGroupException otherwise): `senderMembership` in the result
     * is then about that Group.
     * @param homeCreatedBy who created that Group, checked against its signed policy: without it "a member of
     * the Group under this subject" could be a member of a Group somebody else put there. std::nullopt is said
     * only by a caller that does not rely on `senderMembership`.
     */
    DecryptedSharedEnvelope decryptShared(
        const Path& authorSubject,
        const Path& place,
        const core::Buffer& envelope,
        const DecryptOptions& options,
        const std::optional<std::string>& homeCreatedBy
    );
    /** The file form of decryptShared. The envelope's Group is checked before the handle is returned. */
    GroupFileReader beginSharedFileDecryption(
        const Path& authorSubject,
        const Path& place,
        const core::Buffer& envelope,
        const DecryptOptions& options,
        const std::optional<std::string>& homeCreatedBy
    );

    /** The ID of the Group `subject` names. */
    std::string groupIdOf(const Path& subject) const;

private:
    std::string create(
        const std::optional<Path>& subject,
        const std::vector<GroupMemberToAdd>& members,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<GroupRules>& rules,
        const std::string& visibleTo
    );
    // Throws unless the Group was opened the way `item` asks: its creator, its fixed roster, or neither.
    void check(const OpenGroupItem& item, const Group& state);
    std::vector<SpaceRecipient> resolve(const std::vector<SpaceRecipient>& recipients);
    void requireHome(
        const Path& authorSubject,
        const core::Buffer& envelope,
        const std::optional<std::string>& homeCreatedBy
    );

    GroupApi _api;
    std::string _contextId;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPCLIENT_HPP_
