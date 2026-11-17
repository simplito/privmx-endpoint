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
 * A membership, key or policy change that failed may still take effect: the Bridge may have applied it and lost or
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
     * @param policies Group's policies. Who may add, remove, rotate and change the policy (`update`, `rotateKeys`,
     * `updatePolicy`, `ownerCanBeRemovedFromManagers`) is signed into the Group's state with the creator;
     * `inherit`/`default` (or absent) mean the built-in defaults (manager, manager, manager, yes), not the
     * Context's; the Context can only deny further. The creator must hold `update` under them, or it could not write the Group's metadata.
     * @return ID of the created Group
     */
    std::string createGroup(
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies = std::nullopt,
        const std::optional<core::Buffer>& idSeed = std::nullopt,
        const std::string& visibleTo = "members"
    );

    /**
     * The ID of a Group created with `idSeed`: every client computes the same one from the Context and the seed,
     * so no server has to be asked which Group belongs to an entity.
     *
     * A seed anybody can compute is a name anybody can take first. Creating a Group under a seed fails when one
     * exists or ever existed; a caller who finds a Group under a derived ID checks `Group::creator` against who
     * owns the entity before trusting it.
     */
    static std::string deriveGroupId(const std::string& contextId, const core::Buffer& idSeed);

    /** `getGroup` for several Groups. One result per ID, in order; a Group that fails reports its own code. */
    std::vector<GroupResult> getGroups(const std::vector<std::string>& groupIds);

    /**
     * The Group's current identity key, read and verified against the Group's latest statement. For a member,
     * and for any user of the Context when the Group is visible to the Context (`setGroupVisibility`).
     */
    GroupPublicKey getGroupPublicKey(const std::string& contextId, const std::string& groupId);

    /**
     * Sets who beside the members may read the Group's identity key, roster and statements: "members" or
     * "context". A manager's call. Making a Group visible to the Context is what lets someone outside it write to
     * it with `encryptAsOutsider`; it also shows the roster to every user of the Context.
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
     * A failed call may still take effect (see the class note).
     *
     * When the caller's own leaf does not open, the removal still goes through (a member that garbled it cannot
     * block its own removal) and, unless this session holds the current Group key, abandons the Group's history for
     * every member. After the caller's identity key changed and Connection::adoptPreviousIdentity was called, it is
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
     * identity key first, then rotate. Charged to the Group's rotation budget; allowed by the `rotateKeys` policy
     * (managers, by default).
     *
     * A failed call may still take effect (see the class note). A call made after it was found applied is a new
     * rotation.
     *
     * @param groupId ID of the Group
     */
    int64_t rotateGroupKey(const std::string& groupId);

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
     * and policies — are three separate calls, each with its own permission on the Bridge. This one cannot
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
     * @param groupId ID of the Group to update
     * @param publicMeta public (unencrypted) metadata
     * @param version current `publicMetaVersion` of the updated Group
     */
    void updateGroupPublicMeta(const std::string& groupId, const core::Buffer& publicMeta, const int64_t version);

    /**
     * Updates a Group's private (encrypted) metadata, and nothing else.
     *
     * The counterpart of `updateGroupPublicMeta`, with its own permission on the Bridge and its own version
     * counter: the version checked is `Group::privateMetaVersion` alone.
     *
     * @param groupId ID of the Group to update
     * @param privateMeta private (encrypted) metadata
     * @param version current `privateMetaVersion` of the updated Group
     */
    void updateGroupPrivateMeta(const std::string& groupId, const core::Buffer& privateMeta, const int64_t version);

    /**
     * Sets a Group's policies, as a signed commit by a member the current policy allows `updatePolicy`.
     *
     * The rules that govern commits (`update`, `rotateKeys`, `updatePolicy`, `ownerCanBeRemovedFromManagers`) and
     * the creator are part of the Group's signed state; every member follows the change along the commit chain. The
     * call is refused for non-members and, before anything is signed, for a member without `updatePolicy`. It may be
     * retried internally when another commit lands concurrently. No key, epoch or roster moves, and neither metadata
     * version moves.
     *
     * A narrowing of `update` refuses metadata written by an author who loses it: this call carries such a plane
     * forward under the caller's name, and is refused before signing when the caller itself would lose `update`
     * while such a plane exists. Until that carry-forward completes (it is retried by this client's next call on the
     * Group if it fails), `getGroup` returns a non-zero `statusCode` for such a plane, also to concurrent readers;
     * any metadata write by a member holding `update` repairs it.
     *
     * @param groupId ID of the Group to update
     * @param policies Group's policies
     */
    void updateGroupPolicy(const std::string& groupId, const core::ContainerPolicy& policies);

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
     * Throws EnvelopeNotARecipientException when the caller is not among the recipients.
     * @param contextId ID of the Context the envelope was written in
     */
    DecryptedSharedEnvelope decryptShared(
        const std::string& contextId,
        const Path& location,
        const Envelope& envelope,
        const DecryptOptions& options
    );

    /**
     * Begins sealing a file for a Group, as one of its members.
     *
     * ## How sealing a file works
     *
     * The library never touches your storage or your network. It converts bytes and hands them straight back;
     * where they come from and where they go is entirely yours. You drive it in three steps:
     *
     *   1. `beginFileEncryption` — name the Group and declare the plaintext size. You get a handle, not data.
     *   2. `encryptFileChunk` — push plaintext in, take ciphertext out. As many times as you like.
     *   3. `finishFileEncryption` — get the envelope.
     *
     * Keep **both** outputs. The ciphertext is the file. The envelope is a small header naming the Group, the
     * key version, the author and the size, and without it nobody can open the ciphertext — not even a member
     * of the Group. Store them however suits you: two files, two columns, the envelope prepended to the
     * ciphertext. The library has no opinion, because it never sees your storage.
     *
     *     FileHandle h = api.beginFileEncryption(groupId, plaintextSize);
     *     while (source.hasMore()) {
     *         sink.write(api.encryptFileChunk(h, source.read(1 << 20)));  // may write nothing; that is normal
     *     }
     *     Envelope envelope = api.finishFileEncryption(h);  // keep this alongside the ciphertext
     *
     * Memory stays flat no matter how large the file — but only if you write each `encryptFileChunk` result
     * out as it arrives. Collecting the ciphertext in a buffer defeats the whole design, and in a WebAssembly
     * build will exhaust the heap.
     *
     * The size is declared up front, as it is for a Store file, and enforced at `finishFileEncryption`:
     * supplying less than you promised is an error, because it cannot be told apart from a file cut short.
     *
     * Calls on one handle may come from several threads; they are applied one at a time, in no guaranteed
     * order, and a call after the handle is finished is refused. Push chunks in order, from one caller, to get
     * the file you meant.
     *
     * @param groupId ID of the Group to seal for
     * @param size total size of the plaintext file, in bytes
     * @return handle to seal file data with
     */
    FileHandle beginFileEncryption(const std::string& groupId, const FileSize size);

    /**
     * Begins sealing a file for a Group without revealing, or proving, who sent it.
     *
     * The file counterpart of `encryptAnonymously`. Driven exactly like `beginFileEncryption` — same
     * `encryptFileChunk`, same `finishFileEncryption`, and the ciphertext it produces is byte-for-byte the
     * same shape. Only the envelope differs, in how it wraps the file key.
     *
     * Needs public information only: the Group's ID and its identity public key. No membership, no server
     * call. A throwaway keypair is generated and discarded, so the result is unattributable — and therefore
     * unreadable to you afterwards. Only the Group can open it.
     *
     * Because nothing about it is attributable, nothing about it is authorised or metered either. If you
     * accept these from the open internet, bound the size and the volume in your own transport.
     *
     * @param groupId ID of the Group to seal for
     * @param groupPubKey the Group's identity public key (base58-DER encoded)
     * @param size total size of the plaintext file, in bytes
     * @return handle to seal file data with
     */
    FileHandle beginFileEncryptionAnonymously(
        const std::string& groupId,
        const std::string& groupPubKey,
        const FileSize size
    );

    /**
     * Seals the next piece of a file: takes plaintext, returns ciphertext.
     *
     * You supply the bytes — nothing is read from anywhere. Blocks may be any size up to 4 MiB and need not
     * align with anything; the library finds its own internal boundaries.
     *
     * The return covers whichever internal chunks this call completed, so it is **empty whenever your block
     * did not finish one**, and larger than your block when it finished several. Neither is an error. Write
     * whatever comes back straight out, in the order it comes back.
     *
     * @param fileHandle handle from `beginFileEncryption` or `beginFileEncryptionAnonymously`
     * @param plainChunk plaintext to append, at most 4 MiB
     * @return ciphertext to store, possibly empty
     */
    core::Buffer encryptFileChunk(const FileHandle fileHandle, const core::Buffer& plainChunk);

    /**
     * Finishes sealing a file and releases its handle.
     *
     * Returns the envelope — the one piece without which the ciphertext is unopenable. Store it.
     *
     * Throws if less plaintext arrived than was declared. The handle is released either way, so there is no
     * need — and no way — to close it again after a failure.
     *
     * @param fileHandle handle from `beginFileEncryption` or `beginFileEncryptionAnonymously`
     * @return the envelope, needed to read the file back
     */
    Envelope finishFileEncryption(const FileHandle fileHandle);

    /**
     * Begins opening a sealed file.
     *
     * ## How opening a file works
     *
     * The mirror of sealing, and again the library is only a converter: you fetch the ciphertext from
     * wherever you put it, push it through, and take plaintext out.
     *
     *     FileHandle h = api.beginFileDecryption(envelope);
     *     while (storage.hasMore()) {
     *         sink.write(api.decryptFileChunk(h, storage.read(1 << 20)));
     *     }
     *     DecryptedFileInfo info = api.finishFileDecryption(h);  // who sent it, and was it whole
     *
     * Feed the ciphertext in the order it was produced. Block sizes need not match the ones used when
     * sealing, and need not match each other.
     *
     * To read only part of a file rather than all of it, see `seekInEncryptedFile`.
     *
     * Accepts envelopes from both `beginFileEncryption` and `beginFileEncryptionAnonymously`; which one it
     * was is reported by `finishFileDecryption`.
     *
     * @param envelope envelope returned by `finishFileEncryption`
     * @return handle to open file data with
     */
    FileHandle beginFileDecryption(const Envelope& envelope);

    /**
     * Opens the next piece of a file: takes ciphertext, returns plaintext.
     *
     * You supply the bytes. Note the difference from `StoreApi::readFromFile`, which fetches for you and
     * takes a *length* as its second argument — here the second argument is the data itself, and nothing is
     * fetched.
     *
     * As on the sealing side, the return covers whichever internal chunks this call completed: empty when it
     * completed none, several chunks' worth when it completed several.
     *
     * @param fileHandle handle from `beginFileDecryption`
     * @param cipherChunk ciphertext to append, at most 4 MiB
     * @return plaintext, possibly empty
     */
    core::Buffer decryptFileChunk(const FileHandle fileHandle, const core::Buffer& cipherChunk);

    /**
     * Moves the read cursor to `position` in the plaintext, and returns where to resume feeding ciphertext.
     *
     * ## Why it returns an offset rather than just moving a cursor
     *
     * You are the source of the bytes, so the library cannot fetch anything for you — it can only tell you
     * what to fetch. And it has to tell you, because the two coordinate spaces do not line up: the file is
     * sealed in chunks, each slightly larger than the plaintext it carries, so plaintext byte 1'000'000 does
     * not sit at ciphertext byte 1'000'000. Only the library knows that mapping.
     *
     * A chunk is also the smallest thing that can be opened, so the offset you get back points at the start
     * of the chunk *containing* `position`, never at `position` itself. The head of that chunk is then
     * discarded for you, so what comes out of the next `decryptFileChunk` still begins exactly at `position`.
     *
     * ## Reading a range
     *
     * To read `length` plaintext bytes starting at `from`:
     *
     *     FileHandle h = api.beginFileDecryption(envelope);
     *     CipherOffset at = api.seekInEncryptedFile(h, from);
     *
     *     std::string out;
     *     while (out.size() < length) {
     *         core::Buffer block = storage.read(at, 1 << 20);  // your storage, your transport
     *         if (block.size() == 0) break;                    // ran off the end of the ciphertext
     *         at += block.size();
     *         out += api.decryptFileChunk(h, block).stdString();
     *     }
     *     out.resize(length);                                  // front is exact, tail may overshoot
     *     api.finishFileDecryption(h);
     *
     * The output starts exactly where you asked and may run past where you stopped asking, because opening
     * happens a whole chunk at a time — trim the tail yourself. Stop feeding as soon as you have enough;
     * there is no need to read on to the end of the file.
     *
     * Seek as often as you like on one handle, forwards or backwards. Anything buffered from the previous
     * position is discarded.
     *
     * ## What it is for
     *
     * Playing media from the middle, reading a header out of a large file without transferring the rest,
     * building a preview, resuming an interrupted read, or answering HTTP range requests from sealed storage.
     *
     * ## What it costs
     *
     * Seeking gives up the truncation guarantee for this handle, and `DecryptedFileInfo::complete` comes back
     * false to say so. A reader that deliberately skips most of a file cannot also confirm the skipped parts
     * were ever there.
     *
     * Everything you *do* read stays fully authenticated: a chunk cannot be forged, reordered, moved to a
     * different position in the file, or lifted from another file. Only "is the rest of it present" becomes
     * unanswerable. If you need that guarantee as well, read the file start to finish on a separate handle.
     *
     * @param fileHandle handle from `beginFileDecryption`
     * @param position new cursor position in the plaintext, from 0 to the file size
     * @return ciphertext byte offset to resume feeding from
     */
    CipherOffset seekInEncryptedFile(const FileHandle fileHandle, const FilePosition position);

    /**
     * Finishes opening a file, reports where it came from, and releases its handle.
     *
     * Call it even when you are sure you are done. Each chunk verifies on its own, so a missing tail is
     * detectable here and nowhere else: this is the only point at which "the file ended early" can be
     * distinguished from "the file ended".
     *
     * Throws if less ciphertext arrived than the envelope declares — unless you seeked, in which case a short
     * read is what you asked for, and it reports `complete = false` instead of throwing. The handle is
     * released either way.
     *
     * The provenance arrives here rather than at `beginFileDecryption` because this is the first moment the
     * file is known to have been received whole; attributing it earlier would attribute something that might
     * still turn out to be truncated. Check `DecryptedFileInfo::type` before trusting `authorPubKey`, and
     * `DecryptedFileInfo::complete` before treating the file as whole.
     *
     * @param fileHandle handle from `beginFileDecryption`
     * @return which Group the file was sealed for, who — if anyone — is provably its author, and whether all
     *         of it arrived
     */
    DecryptedFileInfo finishFileDecryption(const FileHandle fileHandle);

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
