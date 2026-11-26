#ifndef _PRIVMXLIB_ENDPOINT_GROUP_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_TYPES_HPP_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/Types.hpp"

namespace privmx {
namespace endpoint {
namespace group {

// Aliases, not distinct types: nothing stops you passing a FileSize where a FileHandle belongs. They exist
// so the file API's int64_t signatures state their own meaning in the generated docs and the bindings.

/** A sealed envelope, as produced by `encrypt` / `encryptAnonymously` / `finishFileEncryption`. */
using Envelope = core::Buffer;
/** An open encrypted-file handle. Opaque — its numeric value carries no meaning. */
using FileHandle = int64_t;
/** A length in bytes of file plaintext. */
using FileSize = int64_t;
/** A position in bytes within a file's plaintext. */
using FilePosition = int64_t;
/** A position in bytes within a file's *ciphertext* — what `seekInEncryptedFile` hands back. */
using CipherOffset = int64_t;
/** An open sequence, being written or read. Opaque. */
using SequenceHandle = int64_t;

/**
 * Holds all available information about a Group.
 */
/**
 * One member to seat, and the role they take.
 *
 * The role travels per member rather than per call: seating a manager and a user together is one delta over the
 * union of their paths, and splitting it into two calls would be two of everything for no reason.
 */
struct GroupMemberToAdd {
    core::UserWithPubKey user;
    /** "user" or "manager". */
    std::string role;
};

/** A member of a group and the role it is given by GroupApi::setGroupRoles. */
struct GroupRoleChange {
    std::string userId;
    /** "user" or "manager". */
    std::string role;
};

/**
 * Who may change what in a Group, as the Group's signed statements bind it. Each value is a policy entry: "manager",
 * "user", "owner", "all", "none", or alternatives joined with "," ("manager,owner").
 */
struct GroupRules {
    /** Who may add members. */
    std::string addMembers;
    /** Who may remove members or replace their keys. */
    std::string removeMembers;
    /** Who may rewrite the Group's metadata (the policy's `update`). */
    std::string updateMeta;
};

/** The rules GroupApi::updateGroupRules changes; an unset one stays as it is. */
struct GroupRulesUpdate {
    std::optional<std::string> addMembers;
    std::optional<std::string> removeMembers;
    std::optional<std::string> updateMeta;
};

/** One signed statement of a Group's history, as GroupApi::getGroupLog returns it. */
struct GroupLogEntry {
    /** 1 for the creation, one more for each later statement. */
    int64_t seq;
    /** "create", "add", "remove", "reseat" (a member's key replaced, see GroupApi::replaceGroupMemberKeys), "roles", "rotate", "policy" or "selfUpdate". */
    std::string kind;
    /** The member who signed it, and the identity key it was signed with. */
    std::string author;
    std::string authorPubKey;
    /** The author's clock, in milliseconds. */
    int64_t date;
    /** The Group's key epoch and roster version after it. */
    int64_t keyVersion;
    int64_t rosterVersion;
    /** For "add": who joined as a user or as a manager. For "roles": who became one. */
    std::vector<std::string> addedUsers;
    std::vector<std::string> addedManagers;
    /** For "remove": who left. For "reseat": whose key was replaced. */
    std::vector<std::string> removed;
};

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
     * Group identity public key (base58-DER encoded); empty when the Group's latest signed commit statement
     * could not be verified to vouch for it
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
     * Public-metadata version. Changes only on `updateGroupPublicMeta`.
     */
    int64_t publicMetaVersion;

    /**
     * Private-metadata version. Changes only on `updateGroupPrivateMeta`.
     */
    int64_t privateMetaVersion;

    /**
     * Roster version. Changes only on a membership change (`addGroupMembers`/`removeGroupMembers`).
     */
    int64_t rosterVersion;

    /**
     * Group's public metadata
     */
    core::Buffer publicMeta;

    /**
     * Group's private metadata
     */
    core::Buffer privateMeta;

    /**
     * Group's policies. Only `update`, `rotateKeys`, `updatePolicy` and `ownerCanBeRemovedFromManagers` (and the
     * creator) are signed into the Group's state; there `inherit`/`default` mean the built-in defaults (manager,
     * manager, manager, yes), not the Context's; the Context can only deny further. Every other field is the
     * Bridge's word.
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

    /**
     * "members" or "context": who beside the members may read the Group's identity key, roster and statements,
     * and so write to it from outside. The Bridge's own setting; no statement signs it.
     */
    std::string visibleTo;

    /**
     * the Group's signed rules, resolved (GroupRules). Empty strings when the policy served does not parse
     */
    GroupRules rules;
};

/**
 * Holds the information about a Group that a listing serves: identity, epoch, counters and policies.
 *
 * Every field is of constant size, so a page does not grow with the Groups' membership or age. A listing
 * deliberately carries no roster and no per-Group state — no `users`/`managers` (they grow with membership),
 * no encrypted data, key entries, history, tree or signed statement. So there is
 * no `publicMeta`/`privateMeta` here (nothing to decrypt from), no `schemaVersion` (it is recorded inside the
 * encrypted data), and no `statusCode` (nothing was decrypted or verified, so there is no status to report).
 * Call `getGroup` for any of those.
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
     * Group identity public key (base58-DER encoded). Non-empty only when it is exactly the grant key, at the
     * listed `keyVersion`, of a state this process has already verified for the Group (its latest signed commit
     * statement, vouched for by the UserVerifier, and pinned) — through `getGroup`, an own commit or a write to a
     * container granted to the Group. Empty otherwise, including on the first listing in a process: call
     * `getGroup` to verify the Group and get its key.
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
     * Public-metadata version. Changes only on `updateGroupPublicMeta`.
     */
    int64_t publicMetaVersion;

    /**
     * Private-metadata version. Changes only on `updateGroupPrivateMeta`.
     */
    int64_t privateMetaVersion;

    /**
     * Roster version. Changes only on a membership change (`addGroupMembers`/`removeGroupMembers`).
     */
    int64_t rosterVersion;

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

    /** "members" or "context"; see `Group::visibleTo`. */
    std::string visibleTo;
};

/**
 * Which key an envelope was sealed with, and therefore what its author field is worth.
 */
enum EnvelopeType : int64_t {
    /** Sealed with the Group's symmetric data key by a member, and signed by them. */
    ENVELOPE_FROM_MEMBER = 1,
    /** Sealed to the Group's identity public key by an outsider using a throwaway keypair. Unattributable. */
    ENVELOPE_ANONYMOUS = 2,
    /** Sealed to the Group's identity public key by someone who is not a member, and signed by them. */
    ENVELOPE_FROM_OUTSIDER = 3,
};

/**
 * One segment of a path in the application's own data: a name written in code ("chat", "body") or an
 * identifier that comes from data (a chat ID). The two never collide: "ab" as a name and the bytes 0x61 0x62 as
 * an identifier are different segments.
 */
struct PathSegment {
    /** false: `value` is a UTF-8 name written in code. true: `value` is the bytes of an identifier. */
    bool isId;
    core::Buffer value;
};

/** A path in the application's own data. An envelope is bound to one: it opens only with the same path. */
using Path = std::vector<PathSegment>;

/** The verified author of a member's envelope. */
struct EnvelopeAuthor {
    std::string userId;
    /** Base58-DER. The key the envelope was signed with; the UserVerifier accepted it for `userId`. */
    std::string pubKey;
    /**
     * "user" or "manager": the author's role in the Group **now**. The Group's past rosters are not kept, so
     * this is not the role they had when they wrote.
     */
    std::string role;
};

/** A verified writer who is not a member of the Group the envelope was read with. */
struct EnvelopeSender {
    std::string userId;
    /** Base58-DER. */
    std::string pubKey;
};

/** Who else an envelope was written for (`EncryptOptions::alsoFor`). Signed by the writer. */
struct EnvelopeAudience {
    std::vector<std::string> groups;
    std::vector<std::string> users;
};

/** What `decrypt` returns: a member's envelope, opened. */
struct DecryptedEnvelope {
    core::Buffer data;
    EnvelopeAuthor author;
    /** The epoch of the Group key it was sealed under. */
    int64_t keyVersion;
    /** The author's clock, signed, in milliseconds. Not proof of when it was written. */
    int64_t encryptedAt;
    EnvelopeAudience sharedWith;
};

/**
 * Every read says whose writing it expects. Exactly one of `expectedAuthor` and `anyAuthor` must be set; with
 * neither the call throws EnvelopeAuthorNotStatedException, so the question cannot be skipped.
 */
struct DecryptOptions {
    /**
     * The author about to be displayed: usually the one the application's server names next to the envelope.
     * A different author fails with EnvelopeWrongAuthorException.
     */
    std::string expectedAuthor;
    /** Set instead of `expectedAuthor` when the author is shown from the result, never from elsewhere. */
    bool anyAuthor = false;
    /** For content that arrived as new: refuse an envelope from an epoch older than the current one. */
    bool currentEpochOnly = false;
};

/** One envelope to read with `decryptMany`. */
struct DecryptItem {
    core::Buffer envelope;
    Path location;
    DecryptOptions options;
};

/** Who or what a failure is about. Only the fields that apply are filled. */
struct GroupErrorDetails {
    /** The user and key in question: who really signed, or whose key the UserVerifier refused. */
    std::string userId;
    std::string pubKey;
    /** On a wrong kind of envelope: what it is - "member", "outsider", "anonymous" or "shared". */
    std::string envelopeKind;
};

/** `decryptMany` reports per item. */
struct DecryptResult {
    /** 0 on success; otherwise the code of the exception `decrypt` would have thrown. */
    int64_t statusCode;
    /** Empty unless `statusCode` is 0. */
    DecryptedEnvelope envelope;
    GroupErrorDetails details;
};

/** One more reader of an envelope, beside the Group it is written in. Exactly one field is set. */
struct EnvelopeRecipient {
    /**
     * Another Group, by its ID. The caller need not be in it. The Group is named, not given as a key: its
     * current, verified key is fetched at every encryption, so a key from before a removal cannot be used.
     */
    std::string groupId;
    /** One user. Their key goes through the UserVerifier first. */
    std::optional<core::UserWithPubKey> user;
};

struct EncryptOptions {
    std::vector<EnvelopeRecipient> alsoFor;
};

/** What `decryptFromOutsider` returns: written to the Group, and signed, by someone who is not a member. */
struct DecryptedOutsiderEnvelope {
    core::Buffer data;
    /** The epoch of the Group key it was sealed to. */
    int64_t keyVersion;
    EnvelopeSender sender;
    /** The sender's clock, signed, in milliseconds. */
    int64_t encryptedAt;
    EnvelopeAudience sharedWith;
};

/** What `decryptAnonymous` returns. No sender: anyone who knows the Group's public key could have written it. */
struct DecryptedAnonymousEnvelope {
    core::Buffer data;
    /** The epoch of the Group key it was sealed to. */
    int64_t keyVersion;
};

/** What `decryptShared` returns: written in another Group and shared with the caller through `alsoFor`. */
struct DecryptedSharedEnvelope {
    core::Buffer data;
    EnvelopeSender sender;
    /** The Group it says it was written in. The writer's claim; see `senderMembership`. */
    std::string homeGroupId;
    /**
     * "member", "notMember" or "unknown": whether the sender is a member of `homeGroupId` now. "unknown" when
     * the caller cannot see that Group's roster. Anyone in the Context can address an envelope to a Group or a
     * user and write any `homeGroupId` into it: only "member" says it came from inside that Group.
     */
    std::string senderMembership;
    /** How the caller had access: "user", or the ID of the recipient Group the caller is a member of. */
    std::string via;
    int64_t encryptedAt;
    EnvelopeAudience sharedWith;
};

/** `getGroups` reports per Group, the way lists do elsewhere in the Endpoint. */
struct GroupResult {
    /** 0 on success; otherwise the code of the exception `getGroup` would have thrown. */
    int64_t statusCode;
    /** Meaningful only when `statusCode` is 0. */
    Group group;
};

/**
 * A Group's current identity key, verified against the Group's latest statement. What a writer outside the
 * Group seals to. Stale after the Group's next removal or rotation: fetch it when it is needed, do not store it.
 */
struct GroupPublicKey {
    std::string groupId;
    int64_t keyVersion;
    /** Base58-DER. */
    std::string pubKey;
    /**
     * Who created the Group. The Bridge's field, held to the Group's latest signed statement: the creator is
     * part of the policy every statement signs.
     */
    std::string creator;
};

struct GroupEpochRef {
    std::string groupId;
    int64_t keyVersion;
};

/** The part of an envelope readable without any key. Not authenticated: for refusing writes early. */
struct EnvelopeHeader {
    int64_t version;
    std::string groupId;
    /** The epoch the writer claims. 0 for an envelope written from outside the Group. */
    int64_t keyVersion;
    /** true when the writer is not a member of `groupId`: read it with decryptFromOutsider or decryptAnonymous. */
    bool fromOutsider;
    /** true when a writer signed it. Always true for a member's envelope. */
    bool isSigned;
    bool isFile;
    /** false for an envelope written with GroupApi::noLocation(). A server can refuse those. */
    bool hasLocation;
    /** The writer's claim, for a signed envelope; empty otherwise. */
    std::string authorUserId;
    /** Set when the envelope is the header of a sequence: the id its items and marks carry. */
    std::string sequenceId;
    /**
     * Set when the envelope was written in a Space. `keyVersion` is then the version of the Space's key, and
     * `groupId` the Group the author wrote through (empty for an author who is a recipient themselves).
     */
    std::string spaceId;
    std::vector<GroupEpochRef> alsoForGroups;
    std::vector<std::string> alsoForUsers;
};

/**
 * What is known about a decrypted file. Which fields are set follows from the call that opened it, exactly
 * as with envelopes - an opening call reads one kind of file and refuses the others:
 *   beginFileDecryption              `author` (a member, with a role)
 *   beginFileDecryptionFromOutsider  `sender`
 *   beginAnonymousFileDecryption     neither: nobody signed it
 *   beginSharedFileDecryption        `sender`, and the three fields about its origin
 *   beginFileDecryptionInSpace       `sender`, `via`, and `senderMembership` as SpaceOrigin::authorAccess
 * A sender is never reported as an author.
 */
struct DecryptedFileInfo {
    std::optional<EnvelopeAuthor> author;
    std::optional<EnvelopeSender> sender;
    /** For a shared file only: as in DecryptedSharedEnvelope. */
    std::string homeGroupId;
    /** For a shared file as in DecryptedSharedEnvelope; for a file in a Space, SpaceOrigin::authorAccess. */
    std::string senderMembership;
    /** For a shared file as in DecryptedSharedEnvelope; for a file in a Space, SpaceOrigin::via. */
    std::string via;
    EnvelopeAudience sharedWith;
    /** The epoch of the Group key the envelope was sealed to. 0 for a shared file. */
    int64_t keyVersion;
    /** The size of the plaintext, as the envelope states it. */
    int64_t size;
    /**
     * true when every chunk the envelope lists was read. false after a seek: the parts read are the
     * writer's, the whole file is not proven.
     */
    bool complete;
};

/** Where in the ciphertext a range of the plaintext lives. */
struct CipherRange {
    int64_t offset;
    int64_t length;
};

/** The plain part of a sequence item, checkpoint or close. Not authenticated. */
struct SequenceItemHeader {
    std::string sequenceId;
    /** An item's position; for a mark, how many items it covers. */
    int64_t index;
    bool isMark;
};

/** What appendToSequence produced: send both, in this order. */
struct SequenceAppendResult {
    core::Buffer item;
    /** An automatic checkpoint, when one was due. */
    std::optional<core::Buffer> mark;
};

/**
 * One decrypted item of a sequence. Not yet the author's: until a later mark verifies, another member
 * could have forged it. verifySequenceMark says how many items are attested.
 */
struct SequenceItem {
    core::Buffer data;
    /** Position in the sequence, from 0. */
    int64_t index;
    /** How many items before this one never arrived. 0 when nothing was skipped. */
    int64_t missing;
};

/** What a checkpoint or a close proved. */
struct SequenceMarkInfo {
    /**
     * Items attestedFrom .. attestedItems-1 are exactly what the author wrote, in that order. Earlier items are
     * covered only if every earlier mark verified: after a mark that threw, this one attests only from that mark on.
     */
    int64_t attestedFrom;
    /** One past the last item this mark attests: the number of items the author had written at the mark. */
    int64_t attestedItems;
    /** true for a close: the author wrote nothing after it. */
    bool closed;
};

// ── Spaces: one key for several Groups ──

/** Who a Space's key is wrapped for. Exactly one of `groupId` and `user` is set. */
struct SpaceRecipient {
    std::string groupId;
    std::optional<core::UserWithPubKey> user;
    /** "manager" may change the recipients and the meta. Everyone may write, read, and replace the key. */
    std::string role;
};

/** A recipient to remove. Exactly one field is set. */
struct SpaceRecipientRef {
    std::string groupId;
    std::string userId;
};

struct SpaceGroupRecipient {
    std::string groupId;
    std::string role;
    /** The Group's epoch the current key is wrapped for. */
    int64_t keyVersion;
};

struct SpaceUserRecipient {
    std::string userId;
    std::string pubKey;
    std::string role;
};

struct SpaceState {
    std::string spaceId;
    std::string contextId;
    /** Who created the Space: the signer of its first statement. */
    std::string createdBy;
    std::vector<SpaceGroupRecipient> groups;
    std::vector<SpaceUserRecipient> users;
    int64_t keyVersion;
    /**
     * true when a recipient Group has had a removal since the key was made: whoever was removed still holds
     * this key. The next write by anyone who can reach every recipient Group's key replaces it.
     */
    bool keyIsStale;
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    int64_t publicMetaVersion;
    int64_t privateMetaVersion;
};

/** How the author of a value in a Space had access to it. */
struct SpaceOrigin {
    EnvelopeSender author;
    /** "user", or the ID of the Group the author wrote through. Signed by the author. */
    std::string via;
    /**
     * "yes", "no" or "unknown": whether the author is a recipient - themselves, or as a member of `via` - at
     * the time of the read. "unknown" when `via` is a Group whose roster the caller cannot see. The key alone
     * does not answer this: a member removed from a Group keeps the Space's key until it is replaced.
     */
    std::string authorAccess;
    /** The version of the Space's key the value was sealed under. */
    int64_t keyVersion;
};

/** One signed statement of a Space's history, as GroupApi::getSpaceLog returns it. */
struct SpaceLogEntry {
    /** 1 for the creation, one more for each later statement. */
    int64_t seq;
    /** "create", "add", "remove" or "rotate". */
    std::string kind;
    /** The recipient who signed it, and the identity key it was signed with. */
    std::string author;
    std::string authorPubKey;
    /** "user", or the ID of the recipient Group the author acted through (shown by that Group's key). */
    std::string via;
    /** The author's clock, in milliseconds. */
    int64_t date;
    /** The version of the Space's key after it. */
    int64_t keyVersion;
    std::vector<std::string> addedGroups;
    std::vector<std::string> addedUsers;
    std::vector<std::string> removedGroups;
    std::vector<std::string> removedUsers;
};

struct DecryptedSpaceEnvelope {
    core::Buffer data;
    SpaceOrigin origin;
    /** The author's clock, signed. Not proof of when it was written. */
    int64_t encryptedAt;
};

/** `decryptManyInSpace` reports per item. */
struct SpaceDecryptResult {
    int64_t statusCode;
    DecryptedSpaceEnvelope envelope;
    GroupErrorDetails details;
};

enum EventType : int64_t {
    GROUP_CREATE = 0,
    GROUP_UPDATE = 1,
    GROUP_DELETE = 2,
    SPACE_CREATE = 3,
    SPACE_UPDATE = 4,
    SPACE_DELETE = 5,
};

enum EventSelectorType : int64_t {
    CONTEXT_ID = 0,
    GROUP_ID = 1,
    SPACE_ID = 2,
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_TYPES_HPP_
