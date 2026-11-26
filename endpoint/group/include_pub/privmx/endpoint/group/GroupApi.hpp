#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPI_HPP_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/group/Types.hpp"
#include <privmx/endpoint/core/BaseApiClass.hpp>

namespace privmx {
namespace endpoint {
namespace group {

class GroupApiImpl;

/**
 * 'GroupApi' is a class representing Endpoint's API for Groups.
 *
 * A membership, key or rules change that failed may still take effect: the Bridge may have applied it and lost or
 * refused the answer. For a bounded time, or until the Group changes in some other way, this client resends that
 * change before it makes any other change to the Group: a retry of the same call resends it (and returns once it is
 * found applied), and a different call completes it first. Key refreshes never hold anything back.
 *
 * This client runs no thread of its own. Upkeep it finds due (key refreshes of its own path, repairs of the epoch
 * ladder) runs at the end of a later call on the same Group that succeeded (addGroupMembers, removeGroupMembers,
 * rotateGroupKey, renewLeaf, update*, getGroup); it adds latency to that call but never changes its result or throws.
 * A client that makes no such call does none of it. Verified group state is saved to the PinStore by the call that
 * verified it, container key lookups included.
 */
class GroupApi : public privmx::endpoint::core::BaseApiClass<GroupApiImpl> {
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
    GroupApi() = default;

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
     * @param rules Group's rules (GroupRules), signed into the Group's state with the creator; an unset one takes
     * its default ("managers"; `trimHistory` "nobody"). GroupRulesUpdate::createImmutable is the preset of a Group whose membership, roles
     * and rules never change. The creator must hold `editPublicMeta` and `editPrivateMeta` under them, or it could
     * not write the Group's metadata.
     * @return ID of the created Group
     */
    std::string createGroup(
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<GroupRulesUpdate>& rules = std::nullopt,
        const std::optional<core::Buffer>& idSeed = std::nullopt,
        const std::string& visibleTo = "members"
    );

    /**
     * The ID of a Group created with `idSeed`: every client computes the same one from the Context and the seed,
     * so no server has to be asked which Group belongs to an entity.
     *
     * A seed anybody can compute is a name anybody can take first. Creating a Group under a seed fails when one
     * exists or ever existed; a caller who finds a Group under a derived ID checks who created it against who owns
     * the entity before trusting it: `Group::creator` for a member, `GroupPublicKey::creator` (getGroupPublicKey)
     * for a writer outside the Group, before `encryptAsOutsider` or naming it in `alsoFor`.
     */
    static std::string deriveGroupId(const std::string& contextId, const core::Buffer& idSeed);

    /** `getGroup` for several Groups. One result per ID, in order; a Group that fails reports its own code. */
    std::vector<GroupResult> getGroups(const std::vector<std::string>& groupIds);

    /**
     * The Group's current identity key, read and verified against the Group's latest statement. For a member,
     * and for any user of the Context when the Group is visible to the Context (`setGroupVisibility`). `creator`
     * is held to the same statement: what a writer outside the Group checks a Group found by `deriveGroupId` by.
     */
    GroupPublicKey getGroupPublicKey(const std::string& contextId, const std::string& groupId);

    /**
     * Sets who beside the members may read the Group's identity key, roster and statements: "members" or
     * "context". Allowed by the `changeVisibility` rule (checked here on a verified read, and by the Bridge); the
     * visibility itself is the Bridge's setting, not signed. Making a Group visible to the Context is what lets
     * someone outside it write to it with `encryptAsOutsider`; it also shows the roster to every user of the Context.
     */
    void setGroupVisibility(const std::string& groupId, const std::string& visibleTo);

    /**
     * Adds members to a tree-backed Group, without advancing its key epoch.
     *
     * Not `k` separate additions bundled: the newcomers' paths overlap, so this re-keys their union once and
     * lands under a single compare-and-swap. Because the epoch does not move, every container the Group can read
     * stays valid and nobody else re-keys anything.
     *
     * Incremental: only the newcomers are named. The resulting roster is derived from the Group's own verified
     * history, and its metadata carries through untouched — seating a member is not a metadata edit, and
     * `updateGroupPublicMeta`/`updateGroupPrivateMeta` are where that happens.
     *
     * A failed call may still take effect (see the class note); it is resent only while the UserVerifier still
     * vouches for the newcomers' keys.
     *
     * Allowed by the `addMembers` rule; adding a manager also needs `changeRoles`.
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
     * Allowed by the `removeMembers` rule; removing a manager also needs `changeRoles`. The caller cannot remove
     * itself (it mints the new epoch's key, so it would hold the key meant to exclude it): another member removes
     * it. Refused when it would leave a Group that has managers with none. A failed call may still take effect (see
     * the class note).
     *
     * When the caller's own leaf does not open, the removal still goes through (a member that garbled it cannot
     * block its own removal) and, unless this session holds the current Group key, abandons the Group's history for
     * every member (under the removal's own rules, no `trimHistory`). After the caller's identity key changed and Connection::adoptPreviousIdentity was called, it is
     * refused instead while the previous key still opens the leaf: call renewLeaf first.
     *
     * @param groupId ID of the Group
     * @param userIds IDs of the members to remove
     */
    int64_t removeGroupMembers(const std::string& groupId, const std::vector<std::string>& userIds);

    /**
     * Replaces the Group's key without changing who is in it: the key epoch advances, and a fresh Group key is
     * wrapped to the same members, the caller included — also when the caller is the Group's only member.
     *
     * For when a Group key may have leaked without anybody's own identity key: every container granted to the
     * Group goes stale, as after a removal, so their owners can re-key them onto the new epoch. Do that only from a
     * session that has read the Group after this call (the caller's own session does): one that has not may still
     * take the old key for the current one. Content sealed before stays readable to the members.
     *
     * Not a remedy for a lost device: a device holding the identity key opens the new epoch as well. Change the
     * identity key first, then rotate. Charged to the Group's rotation budget; any member may rotate.
     *
     * A failed call may still take effect (see the class note). A call made after it was found applied is a new
     * rotation.
     *
     * @param groupId ID of the Group
     */
    int64_t rotateGroupKey(const std::string& groupId);

    /**
     * The forward-secrecy checkpoint: a rotation whose new epoch publishes no rung down to the earlier ones, after
     * which the Bridge raises the Group's era floor to it and deletes the rungs and archived epoch keys below.
     * From then on nobody can derive a key of an epoch before the cut, neither from the current keys nor from
     * anything the Bridge still stores; members keep only the keys already cached on their own devices, and a member
     * added later reads nothing from before the cut.
     *
     * Allowed by the `trimHistory` rule ("nobody" by default), checked before anything is signed. Both metadata
     * planes are carried up to the new epoch, as after a rotation. Charged to the rotation budget like
     * rotateGroupKey; containers granted to the Group go stale and are re-keyed onto the new epoch.
     *
     * A Space that still holds the Group at an epoch below the new floor makes the Bridge refuse the cut
     * (GroupHistoryInUseException): rotate those Spaces onto the Group's current epoch first, then cut.
     *
     * @param groupId ID of the Group
     * @return the Group's key epoch after the cut
     */
    int64_t cutHistory(const std::string& groupId);

    /**
     * Lets members back in after their identity key was replaced and they cannot renew their own leaf (renewLeaf
     * needs the previous key): everything they could open is re-keyed, the key epoch advances **once**, and the
     * caller's new wraps go to the identity keys the Context lists for them now. They keep their seats, their roles
     * and their place on the roster; whoever still holds a previous key reads nothing written from here on.
     *
     * The members' current keys go through the Connection's UserVerifier like any key this client wraps to: with
     * key continuity on (Connection::useKeyContinuity), accept the change first (Connection::acceptKeyChange).
     *
     * Allowed by the `replaceMemberKeys` rule. The caller cannot be among `userIds`. A failed call may still take
     * effect (see the class note).
     *
     * @param groupId ID of the Group
     * @param userIds IDs of the members whose key is replaced
     * @return the Group's key epoch after the call
     */
    int64_t replaceGroupMemberKeys(const std::string& groupId, const std::vector<std::string>& userIds);

    /**
     * Changes the role of members already in the Group. No key moves: a role decides what the Bridge and the other
     * members accept from somebody, not what they can read.
     *
     * Allowed by the `changeRoles` rule. Refused when it would leave a Group that has managers with none. A failed
     * call may still take effect (see the class note).
     *
     * A demotion refuses a metadata plane written by an author who loses that plane's rule with it: carried
     * forward under the caller's name as for updateGroupRules.
     *
     * @param groupId ID of the Group
     * @param changes the members and the role each takes ("user" or "manager")
     */
    void setGroupRoles(const std::string& groupId, const std::vector<GroupRoleChange>& changes);

    /**
     * Changes the Group's rules (GroupRules), as a signed commit by a member the current rules allow `changeRules`.
     *
     * The rules and the creator are part of the Group's signed state; every member follows the change along the
     * commit chain. The call is refused for non-members and, before anything is signed, for a member without
     * `changeRules`. It may be retried internally when another commit lands concurrently. No key, epoch or roster
     * moves, and neither metadata version moves.
     *
     * A narrowing of `editPublicMeta` or `editPrivateMeta` refuses that plane when its author loses the rule: this
     * call carries such a plane forward under the caller's name, and is refused before signing when the caller itself
     * would lose that plane's rule while such a plane exists. Until that carry-forward completes (it is retried by
     * this client's next call on the Group if it fails), `getGroup` returns a non-zero `statusCode` for such a plane,
     * also to concurrent readers; any write of the plane by a member holding its rule repairs it.
     *
     * @param groupId ID of the Group
     * @param rules the rules to change; an unset one stays as it is
     */
    void updateGroupRules(const std::string& groupId, const GroupRulesUpdate& rules);

    /**
     * The Group's history: every signed statement since its creation, verified from the first to the one the Group
     * is at now (the chain, what each kind of statement may change, the role of whoever signed it).
     *
     * Reads the whole chain on every call, so its cost grows with the Group's age, not with `limit`.
     *
     * @param groupId ID of the Group
     * @param pagingQuery `skip`, `limit` and `sortOrder` ("asc": oldest first, "desc": newest first)
     * @return the statements in the requested window, and how many there are in all
     */
    core::PagingList<GroupLogEntry> getGroupLog(const std::string& groupId, const core::PagingQuery& pagingQuery);

    /**
     * Re-wraps the caller's own leaf to its current identity key after that key changed in the Context.
     *
     * Call from a session connected with the NEW key, after the Context lists it, and after
     * Connection::adoptPreviousIdentity(previousUserPrivKey) (also without a pin store: it is how this client learns
     * its key changed, so a removal made before renewing is refused rather than abandoning history). Before the
     * directory change, settle every group commit of the old session (retry each call that failed with an unknown
     * outcome until it returns or fails for good) and disconnect it.
     * `previousUserPrivKey` (WIF) is the key the leaf was last wrapped to. One commit per group (a self-update: same
     * epoch, nothing to re-key in containers). Keep the previous key until every renewal returned, then discard it.
     *
     * This restores access; it is not compromise recovery. If the previous key may be compromised, also ask a
     * manager to rotate the group key. Rotation does not help a member the server keeps on an old branch of the
     * group history.
     *
     * @param groupId ID of the Group
     * @param previousUserPrivKey the caller's previous identity private key, in WIF
     * @return true if a commit was made, false if the leaf already opens with the current key
     * @throws LocalStateIntegrityException when the previous key's pin slot in the PinStore fails its integrity check.
     * The app may deliberately delete that slot from its PinStore and retry, accepting that groups without a pin
     * under the current key are then read on trust once, as on first contact.
     */
    bool renewLeaf(const std::string& groupId, const std::string& previousUserPrivKey);

    /**
     * Updates a Group's public (unencrypted) metadata, and nothing else.
     *
     * The three things a Group's metadata used to be updated by one call — public metadata, private metadata
     * and rules — are three separate calls, each with its own permission on the Bridge. This one cannot
     * touch the other two: the request it sends has no field to carry them in, so the permission bounds what
     * the call can *do*, not merely what it is meant for.
     *
     * The membership is not updatable here either: seating a member and re-keying their path is one operation
     * on the Group's key tree, so it goes through addGroupMembers/removeGroupMembers instead.
     *
     * There is no way to skip the version check. The entry commits a tag over the version it lands at, so an
     * update computed against a head that has since moved cannot produce a tag any reader will accept — the
     * version pin is what keeps such an update from landing at all. A caller who loses the check has to re-read
     * the Group and build the update again. The version checked is `Group::publicMetaVersion` alone, so a
     * concurrent private-metadata write cannot make this one lose.
     *
     * Allowed by the `editPublicMeta` rule.
     *
     * @param groupId ID of the Group to update
     * @param publicMeta public (unencrypted) metadata
     * @param version current `publicMetaVersion` of the updated Group
     */
    void updateGroupPublicMeta(const std::string& groupId, const core::Buffer& publicMeta, const int64_t version);

    /**
     * Updates a Group's private (encrypted) metadata, and nothing else.
     *
     * The counterpart of `updateGroupPublicMeta`, with its own permission on the Bridge and its own version
     * counter: the version checked is `Group::privateMetaVersion` alone. Allowed by the `editPrivateMeta` rule.
     *
     * @param groupId ID of the Group to update
     * @param privateMeta private (encrypted) metadata
     * @param version current `privateMetaVersion` of the updated Group
     */
    void updateGroupPrivateMeta(const std::string& groupId, const core::Buffer& privateMeta, const int64_t version);

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
     * The listing carries only fields of constant size: identity, epoch, counters and policies. No roster
     * (`users`/`managers`) and no per-Group metadata. Call `getGroup` for the roster, `publicMeta`/`privateMeta`
     * and the verified status. A listed `groupPubKey` is empty unless it matches a state this process has
     * already verified for the Group (see `GroupSummary::groupPubKey`).
     *
     * @param contextId ID of the Context to get the Groups from
     * @param pagingQuery struct with list query parameters
     * @return struct containing a list of Group summaries
     */
    core::PagingList<GroupSummary> listGroups(const std::string& contextId, const core::PagingQuery& pagingQuery);

    /**
     * "Bound to no location": the one Path accepted where a location goes, for a value that belongs to no spot
     * in the application's data. An empty Path is refused: leaving the location out has to be said.
     *
     * What is given up: the application's server can move such an envelope to another record of the same
     * Group, or hand back an older one, and nothing here notices. The author, the epoch and the Group are
     * checked as always. An envelope written with no location never opens with one, and the other way round
     * (EnvelopeWrongLocationException both ways).
     */
    static Path noLocation();

    /**
     * The bytes of an identifier, for a PathSegment with `isId` set. Spells every identifier one way: a UUID
     * (32 hex digits, 8-4-4-4-12, or that in braces; any case) becomes its 16 bytes, anything else its bytes
     * as given, each behind a byte that says which it is. Two clients that spell one identifier differently
     * would otherwise bind to two different paths.
     */
    static core::Buffer idFromString(const std::string& identifier);

    /**
     * The part of an envelope (a message's or a file's) readable without any key: for a server that refuses
     * writes early, such as one from a stale epoch. Nothing in it is authenticated.
     */
    static EnvelopeHeader peekEnvelope(const core::Buffer& envelope);
    /**
     * The plain part of a sequence item or mark. For a server that refuses stale writes: remember the epoch of
     * a sequence when its header arrives (`peekEnvelope` gives its `sequenceId`), then match every item to it.
     */
    static SequenceItemHeader peekSequenceItem(const core::Buffer& itemOrMark);

    /**
     * Seals content for a Group, as one of its members, bound to a location in the application's data.
     *
     * The envelope opens only with the same `location`: a server that stores it under another record gets
     * EnvelopeWrongLocationException on every reader. It is signed with the caller's key and names the caller.
     * `options.alsoFor` adds readers beside the Group: other Groups, single users.
     *
     * @param groupId ID of the Group to seal for; the caller must be a member
     * @param location where the value lives, at least one segment, or `noLocation()`
     * @param content data to encrypt
     * @return the envelope
     */
    Envelope encrypt(
        const std::string& groupId,
        const Path& location,
        const core::Buffer& content,
        const EncryptOptions& options = {}
    );

    /**
     * Opens an envelope written by a member of `groupId` with `encrypt`.
     *
     * Each of the four reading calls takes exactly one kind of envelope and throws EnvelopeWrongKindException
     * for the others:
     *   decrypt              written by a member of this Group
     *   decryptFromOutsider  written to this Group, signed, by a non-member
     *   decryptAnonymous     written to this Group, unsigned
     *   decryptShared        written in another Group, shared through `alsoFor`
     * So what a non-member wrote is never shown as a member's, and what nobody signed is never shown as
     * somebody's.
     *
     * Checked before anything is returned: the envelope names `groupId` (EnvelopeWrongGroupException), it
     * was written for `location` (EnvelopeWrongLocationException), the epoch its header claims is the epoch
     * of the key that opened it, its author is the expected one (EnvelopeWrongAuthorException), the
     * UserVerifier accepts the signing key for that author (EnvelopeUnverifiedAuthorException), and the author
     * is a member of the Group now (EnvelopeAuthorNotMemberException).
     *
     * A removed member keeps the keys of the epochs they were in. For content that arrived as new, set
     * `options.currentEpochOnly` (EnvelopeStaleEpochException), and have the application's server refuse
     * envelopes that are not from the current epoch (`peekEnvelope`).
     */
    DecryptedEnvelope decrypt(
        const std::string& groupId,
        const Path& location,
        const Envelope& envelope,
        const DecryptOptions& options
    );

    /** `decrypt` for a page of envelopes of one Group. Never throws for a bad item: each reports its own code. */
    std::vector<DecryptResult> decryptMany(const std::string& groupId, const std::vector<DecryptItem>& items);

    /**
     * Seals content for a Group the caller is not a member of, signed by the caller: they can write and prove
     * it was them, and cannot read it back. The Group opens it with `decryptFromOutsider`.
     *
     * The Group's current key is read and verified here; none is passed in.
     * @param contextId ID of the Context the Group is in
     */
    Envelope encryptAsOutsider(
        const std::string& contextId,
        const std::string& groupId,
        const Path& location,
        const core::Buffer& content,
        const EncryptOptions& options = {}
    );

    /**
     * Seals content for a Group without revealing, or proving, who sent it.
     * Needs only public information - the Group's ID and its identity public key - and makes no server call.
     * The Group opens it with `decryptAnonymous`, which reports no sender.
     * @param groupPubKey the Group's identity public key (base58-DER encoded)
     */
    Envelope encryptAnonymously(
        const std::string& groupId,
        const std::string& groupPubKey,
        const Path& location,
        const core::Buffer& content
    );

    /**
     * Opens an envelope written to `groupId`, and signed, by someone who is not a member (`encryptAsOutsider`).
     * The sender is who they say; whether they may write here is the application's question to answer.
     */
    DecryptedOutsiderEnvelope decryptFromOutsider(
        const std::string& groupId,
        const Path& location,
        const Envelope& envelope,
        const DecryptOptions& options
    );

    /** Opens an unsigned envelope written to `groupId` (`encryptAnonymously`). There is no sender to report. */
    DecryptedAnonymousEnvelope decryptAnonymous(
        const std::string& groupId,
        const Path& location,
        const Envelope& envelope
    );

    /**
     * Opens an envelope written in another Group and shared with the caller through `alsoFor`: as a user, or
     * as a member of one of the recipient Groups. The caller need not know which. `location` is the one the
     * author wrote it at.
     *
     * The result has a sender, not an author. Check `senderMembership`: anyone in the Context can address an
     * envelope to the caller and name any Group as its origin.
     *
     * Throws EnvelopeNotARecipientException when the caller is not among the recipients, and
     * InvalidParamsException for `options.currentEpochOnly`: a recipient has no epoch of the author's Group to hold
     * the envelope to.
     * @param contextId ID of the Context the envelope was written in
     */
    DecryptedSharedEnvelope decryptShared(
        const std::string& contextId,
        const Path& location,
        const Envelope& envelope,
        const DecryptOptions& options
    );

    // ── Files: the caller moves the bytes, in chunks ──
    //
    // A file comes out as two things: the ciphertext, which `encryptFileChunk` hands back call by call, and the
    // envelope, which `finishFileEncryption` returns. Store both; the envelope is small.
    //
    //     FileHandle h = api.beginFileEncryption(groupId, location);
    //     while (source.hasMore()) sink.write(api.encryptFileChunk(h, source.read(1 << 17)));
    //     Envelope envelope = api.finishFileEncryption(h);
    //
    // The envelope is made when the file ends, and the writer signs in it the size and a digest of every
    // chunk. So the size need not be known up front, a file cut short is detected, and the content is the
    // author's: a member who rewrites the stored ciphertext is caught at the chunk they touched.
    //
    // Every `encryptFileChunk` call returns all the ciphertext of what it was given: nothing is held back for
    // the finish. Each call makes one chunk (more when it is given above 128 KiB), and every chunk costs 36
    // bytes of envelope, so feed it blocks of tens of kilobytes or more, not single lines.
    //
    // ponytail: the chunk list lives in the envelope: 36 bytes per chunk, about 300 KB of envelope per GB at
    // 128 KiB blocks. Move to a Merkle tree with the proofs beside the ciphertext when that is too big.

    /**
     * Begins encrypting a file for a Group, as one of its members.
     *
     * @param groupId ID of the Group
     * @param location where the file lives in the application's data; the envelope opens nowhere else
     * @param options further readers of the file, as for `encrypt`
     * @return handle to encrypt file data with
     */
    FileHandle beginFileEncryption(
        const std::string& groupId,
        const Path& location,
        const EncryptOptions& options = {}
    );

    /** As `beginFileEncryption`, for a writer who is not a member of the Group. The file counterpart of `encryptAsOutsider`. */
    FileHandle beginFileEncryptionAsOutsider(
        const std::string& contextId,
        const std::string& groupId,
        const Path& location,
        const EncryptOptions& options = {}
    );

    /** The file counterpart of `encryptAnonymously`: nobody signs the file, and no server call is made. */
    FileHandle beginFileEncryptionAnonymously(
        const std::string& groupId,
        const std::string& groupPubKey,
        const Path& location
    );

    /**
     * Encrypts the next piece of a file.
     *
     * @param fileHandle handle from one of the `beginFileEncryption...` calls
     * @param plainChunk the next bytes of the file
     * @return their ciphertext, whole; append it to what the earlier calls returned
     */
    core::Buffer encryptFileChunk(const FileHandle fileHandle, const core::Buffer& plainChunk);

    /**
     * Ends the file and releases its handle. When it throws (the Group's or Space's key could not be read, a
     * network error) the handle stays open: call it again, or `abortFile`.
     *
     * @return the file envelope; keep it next to the ciphertext
     */
    Envelope finishFileEncryption(const FileHandle fileHandle);

    /**
     * Releases a file handle of either kind (from a `beginFileEncryption...` or a `beginFileDecryption...` call)
     * without finishing it: no envelope is made, no completeness is checked. For an upload or a read given up.
     */
    void abortFile(const FileHandle fileHandle);

    /**
     * Begins decrypting a file a member of the Group wrote. Checks the envelope exactly as `decrypt` checks a
     * message's: the location, the Group, the kind, and the author - who must be named, or accepted as anyone.
     *
     * @param envelope what `finishFileEncryption` returned
     * @return handle to decrypt file data with
     */
    FileHandle beginFileDecryption(
        const std::string& groupId,
        const Path& location,
        const Envelope& envelope,
        const DecryptOptions& options
    );
    /** The file counterparts of `decryptFromOutsider`, `decryptAnonymous` and `decryptShared`. */
    FileHandle beginFileDecryptionFromOutsider(
        const std::string& groupId,
        const Path& location,
        const Envelope& envelope,
        const DecryptOptions& options
    );
    FileHandle beginAnonymousFileDecryption(const std::string& groupId, const Path& location, const Envelope& envelope);
    FileHandle beginSharedFileDecryption(
        const std::string& contextId,
        const Path& location,
        const Envelope& envelope,
        const DecryptOptions& options
    );

    /**
     * Decrypts the next piece of a file. The ciphertext may be cut any way: bytes that do not yet make a
     * whole chunk wait for the next call, so a call may return nothing.
     *
     * A chunk is checked against the digest the writer put in the envelope before it is returned: every byte
     * that comes out is the writer's. A chunk that was changed, moved or swapped throws
     * `EnvelopeFileCorruptedException` at that chunk. `finishFileDecryption` adds only that the file is complete.
     */
    core::Buffer decryptFileChunk(const FileHandle fileHandle, const core::Buffer& cipherChunk);

    /** Which ciphertext bytes hold plaintext bytes [from, to): for an HTTP Range request. */
    CipherRange getFileCipherRange(const FileHandle fileHandle, const FilePosition from, const FilePosition to);

    /**
     * Moves reading to `position` in the plaintext.
     *
     * A chunk only opens whole, so reading continues from the start of the chunk that holds `position`; the
     * bytes before `position` in it are dropped for you.
     *
     * @return where in the ciphertext to continue reading from
     */
    CipherOffset seekInEncryptedFile(const FileHandle fileHandle, const FilePosition position);

    /**
     * Ends reading and releases the handle. Throws `EnvelopeTruncatedFileException` when chunks the envelope
     * lists never arrived - unless the reader seeked, in which case `complete` is false instead.
     */
    DecryptedFileInfo finishFileDecryption(const FileHandle fileHandle);

    // ── Sequences: many small items from one author, in order ──
    //
    // For what is too frequent to sign one by one: edits of a shared document, live captions, cursors.
    // The author signs once, in the header (an envelope bound to `location`). Each item is then encrypted
    // under the sequence's own key with its position, at the cost of a symmetric operation.
    //
    // What a reader knows about an item:
    // - at once: nobody without the Group's key made, changed, moved or replayed it, and how many items
    //   before it are missing;
    // - after the next checkpoint or the close verifies: the author wrote it. Until then another *member*
    //   could have forged it, because every member can open the header and learn the sequence's key.
    // Sign with encrypt() instead when each item must be the author's the moment it is read.
    //
    // A sequence belongs to one epoch. After a removal or a rotation appendToSequence throws
    // EnvelopeStaleEpochException: begin a new sequence. Old ones stay readable.
    //
    // ponytail: sequences have one audience. Share a sequence by sharing the Group, until someone needs more.

    /**
     * @param checkpointEvery a checkpoint is made by itself after this many items, so a writer cannot forget
     * to make any; 0 turns that off, for a writer that calls checkpointSequence on its own schedule.
     */
    SequenceHandle beginSequence(const std::string& groupId, const Path& location, int64_t checkpointEvery = 64);
    /** The signed header. Send or store it before the items. */
    core::Buffer getSequenceHeader(const SequenceHandle sequence);
    SequenceAppendResult appendToSequence(const SequenceHandle sequence, const core::Buffer& data);
    /** A signature over everything appended so far. Send it like an item. */
    core::Buffer checkpointSequence(const SequenceHandle sequence);
    /** A final checkpoint that also says nothing follows. Frees the handle. */
    core::Buffer finishSequence(const SequenceHandle sequence);

    /**
     * Opens a sequence for reading; checks the header as decrypt() checks an envelope.
     * @param resumeFrom a checkpoint of this sequence to start after, for a reader that joins late or
     * continues another day. Without it, reading starts at item 0.
     */
    SequenceHandle openSequence(
        const std::string& groupId,
        const Path& location,
        const core::Buffer& header,
        const DecryptOptions& options,
        const std::optional<core::Buffer>& resumeFrom = std::nullopt
    );
    /** Items must arrive in order. A skipped one is reported in `missing`; an earlier or repeated one throws. */
    SequenceItem readSequenceItem(const SequenceHandle sequence, const core::Buffer& item);
    /**
     * Checks a checkpoint or a close against the items read. Throws `EnvelopeSequenceOrderException` if any
     * item was missing or forged; reading may go on, and the next mark attests what follows this one only
     * (`SequenceMarkInfo::attestedFrom`), not what came before it.
     */
    SequenceMarkInfo verifySequenceMark(const SequenceHandle sequence, const core::Buffer& mark);
    /** Frees a handle from openSequence, or from beginSequence without finishing it. */
    void closeSequence(const SequenceHandle sequence);

    // ── Spaces: one key for several Groups ──
    //
    // For an application's own container on its own database: records that the same Groups read all the time.
    // alsoFor wraps a value's key once per recipient, for every value. A Space wraps its key once per recipient
    // when it is created and when the key is replaced; writing a value wraps nothing.
    //
    // A Space has a signed history, like a Group: every change of its recipients or its key is a statement signed
    // by a recipient and chained to the one before. The Bridge stores the statements and the wrapped keys; who
    // the recipients are, which key is current and who made the Space is what the statements add up to, replayed
    // and checked here. The Bridge cannot add a recipient or plant a key, and neither can a user of the Context
    // who is no recipient: a statement needs a recipient's own signature, or the key of a recipient Group.
    //
    // A stale key. When a recipient Group removes a member, that member still holds the Space's key. The Bridge
    // marks the Space (SpaceState::keyIsStale), and the next write by someone who can reach every recipient
    // Group's current key makes a new one first. Until then what is written can be read by the removed member,
    // if the application's server gives them the ciphertext. Where that window matters, call rotateSpaceKey
    // right after the removal, or use alsoFor.
    //
    // A Space has its own kind of envelope: decrypt() refuses it and decryptInSpace refuses the others
    // (EnvelopeWrongKindException). No outsiders and no alsoFor: to let someone write, make them a recipient.
    // Files and sequences use the chunk and item calls above with the handles returned here.
    //
    // ponytail: the Space is read from the Bridge at most every 5 seconds per Space, not on every write. A writer
    // notices a stale key up to that much later, unless it is subscribed to the Space's events (SpaceChangedEvent):
    // each one drops the cached read, so the next write reads the Space again.

    /**
     * @param recipients the Groups and users the key is wrapped for; the caller must be among them as a manager,
     * themselves or through a Group
     * @param idSeed when set, the Space's ID is deriveSpaceId(contextId, idSeed) instead of random. A Space deleted
     * and created again under the same derived ID by another user starts again at key version 1, below what this
     * process has seen of the earlier one: it reads as a rollback (GroupHistoryForkException) here, and with a
     * PinStore on this device after a restart too. Re-created by this process, the earlier Space's pin is let go.
     * @return the Space's ID
     */
    std::string createSpace(
        const std::string& contextId,
        const std::vector<SpaceRecipient>& recipients,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<core::Buffer>& idSeed = std::nullopt
    );
    static std::string deriveSpaceId(const std::string& contextId, const core::Buffer& idSeed);
    /**
     * The one spelling of a path, as bytes: what a high-level client gives deriveGroupId and deriveSpaceId as the seed
     * of a Group or Space addressed by its subject. Two paths give the same bytes only when they have the same
     * segments, each of the same kind.
     */
    static core::Buffer encodePath(const Path& path);
    /**
     * Ties a Group to a subject on this device (in the PinStore). Throws GroupSubjectReboundException when the
     * device already knows the subject under another Group. For a high-level client's "open pinned" (a wrapper's GroupClient).
     */
    void pinGroupToSubject(const std::string& contextId, const Path& subject, const std::string& groupId);
    SpaceState getSpace(const std::string& spaceId);
    core::PagingList<SpaceState> listSpaces(const std::string& contextId, const core::PagingQuery& pagingQuery);
    void deleteSpace(const std::string& spaceId);
    /** The current key and every earlier version are wrapped for them: they read what is already there. */
    void addSpaceRecipients(const std::string& spaceId, const std::vector<SpaceRecipient>& recipients);
    /** Makes a new key the removed do not get. @return the new key version */
    int64_t removeSpaceRecipients(const std::string& spaceId, const std::vector<SpaceRecipientRef>& recipients);
    /**
     * Makes a new key, wrapped for every recipient's current key. Throws SpaceRecipientUnavailableException
     * when the caller cannot see a recipient Group's current key.
     * @return the new key version
     */
    int64_t rotateSpaceKey(const std::string& spaceId);
    void updateSpacePublicMeta(const std::string& spaceId, const core::Buffer& meta, int64_t version);
    void updateSpacePrivateMeta(const std::string& spaceId, const core::Buffer& meta, int64_t version);

    /**
     * One symmetric encryption and one signature. When the key is stale, it is replaced first. A caller who may
     * not replace it (a "user" of the Space outside the Group whose key moved) gets EnvelopeStaleEpochException:
     * nothing is written under a key a removed member holds. A manager, or a member of that Group, calls
     * rotateSpaceKey.
     */
    core::Buffer encryptInSpace(const std::string& spaceId, const Path& location, const core::Buffer& data);
    /** `options.currentEpochOnly` means the Space's current key version. */
    DecryptedSpaceEnvelope decryptInSpace(
        const std::string& spaceId,
        const Path& location,
        const core::Buffer& envelope,
        const DecryptOptions& options
    );
    std::vector<SpaceDecryptResult> decryptManyInSpace(
        const std::string& spaceId,
        const std::vector<DecryptItem>& items
    );
    FileHandle beginFileEncryptionInSpace(const std::string& spaceId, const Path& location);
    FileHandle beginFileDecryptionInSpace(
        const std::string& spaceId,
        const Path& location,
        const core::Buffer& envelope,
        const DecryptOptions& options
    );
    SequenceHandle beginSequenceInSpace(const std::string& spaceId, const Path& location, int64_t checkpointEvery = 64);
    SequenceHandle openSequenceInSpace(
        const std::string& spaceId,
        const Path& location,
        const core::Buffer& header,
        const DecryptOptions& options,
        const std::optional<core::Buffer>& resumeFrom = std::nullopt
    );
    /** Who wrote the sequence opened with openSequenceInSpace, and how they had access. */
    SpaceOrigin getSpaceSequenceOrigin(const SequenceHandle sequence);
    /**
     * The Space's history: every change of its recipients and its key, verified from the creation. Each
     * statement is signed by a recipient - themselves, or through a recipient Group, shown by that Group's key.
     */
    core::PagingList<SpaceLogEntry> getSpaceLog(const std::string& spaceId, const core::PagingQuery& pagingQuery);

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

    /**
     * Sends an ephemeral notification to the Group's members — "I am typing", "I moved the cursor", "the call
     * has started".
     *
     * The content is sealed with the Group's own key, exactly as `encrypt` would seal it, and the recipients
     * open it with the key they already hold. So one call sends one request no matter how large the Group is,
     * and members receive it as a `GroupCustomEvent` with the payload already opened and the sender's
     * signature already verified.
     *
     * A notification is not a record: whoever is not connected and subscribed at the time misses it. Anything
     * that has to survive belongs in a Store or a Thread.
     *
     * Requires membership. `eventData` is capped at about 11 KB after sealing and encoding.
     *
     * @param groupId ID of the Group to notify
     * @param channelName name of the channel, chosen by you; recipients subscribe to it with
     *        `buildCustomEventSubscriptionQuery`. Must not contain '/', '|', ',' or '='.
     * @param eventData payload to send
     * @param users IDs of the members to reach; empty means every member
     */
    void sendCustomEvent(
        const std::string& groupId,
        const std::string& channelName,
        const core::Buffer& eventData,
        const std::vector<std::string>& users = {}
    );

    /**
     * Generate subscription Query for custom notifications sent with `sendCustomEvent`.
     *
     * @param channelName name of the channel to listen on — the same name the sender passed
     * @param selectorType scope on which you listen for events
     * @param selectorId ID of the selector
     */
    std::string buildCustomEventSubscriptionQuery(
        const std::string& channelName,
        EventSelectorType selectorType,
        const std::string& selectorId
    );

private:
    // Ceiling on one block handed across the API, so peak memory is a property of the API rather than the
    // caller's discipline — a whole-file call would be a hard failure under WebAssembly's 4 GiB address space.
    static constexpr size_t MAX_FILE_BLOCK = 4 * 1024 * 1024;

    GroupApi(const std::shared_ptr<GroupApiImpl>& impl);
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPI_HPP_
