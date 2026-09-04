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
    void addGroupMembers(const GroupId& groupId, const std::vector<GroupMemberToAdd>& newMembers);

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
    void removeGroupMembers(const GroupId& groupId, const std::vector<std::string>& userIds);

    /**
     * Updates an existing Group's metadata.
     *
     * The membership is deliberately not updatable here: seating a member and re-keying their path is one
     * operation on the Group's key tree, so it goes through addGroupMembers/removeGroupMembers instead.
     *
     * @param groupId ID of the Group to update
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param version current version of the updated Group
     * @param force force update (without checking version)
     * @param forceGenerateNewKey force to regenerate a key for the Group
     * @param policies Group's policies
     */
    void updateGroup(
        const GroupId& groupId,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const int64_t version,
        const bool force,
        const bool forceGenerateNewKey,
        const std::optional<core::ContainerPolicy>& policies = std::nullopt
    );

    /**
     * Deletes a Group by given Group ID.
     *
     * @param groupId ID of the Group to delete
     */
    void deleteGroup(const GroupId& groupId);

    /**
     * Gets a Group by given Group ID.
     *
     * @param groupId ID of the Group to get
     * @return Group struct containing info about the Group
     */
    Group getGroup(const GroupId& groupId);

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
     * Seals content for a Group, as one of its members.
     *
     * The returned envelope is self-contained: it names the Group and the key version it was sealed under, so
     * any member can `decrypt` it later — including after the Group's key has rotated — without being told
     * anything alongside it. It is signed with your own key, so a reader also learns that you wrote it.
     *
     * Requires membership. To seal for a Group you are not in, use `encryptAnonymously`.
     *
     * @param groupId ID of the Group to seal for
     * @param content data to encrypt
     * @return the envelope
     */
    Envelope encrypt(const GroupId& groupId, const core::Buffer& content);

    /**
     * Seals content for a Group without revealing, or proving, who sent it.
     *
     * Needs only public information — the Group's ID and its identity public key, both readable from
     * `Group::groupPubKey` — so it works whether or not you are a member, and makes no server call. A
     * throwaway keypair is generated per call and discarded, which is what makes the result unattributable:
     * members open it with `decrypt`, which reports `ENVELOPE_ANONYMOUS` and no author.
     *
     * You cannot read back what you sealed here. Only the Group can.
     *
     * If the Group later rotates its identity key, envelopes already sealed to the old one stay readable, as
     * long as the Group's history has not been pruned past that point.
     *
     * @param groupId ID of the Group to seal for
     * @param groupPubKey the Group's identity public key (base58-DER encoded)
     * @param content data to encrypt
     * @return the envelope
     */
    Envelope encryptAnonymously(
        const GroupId& groupId,
        const PubKey& groupPubKey,
        const core::Buffer& content
    );

    /**
     * Opens an envelope sealed by `encrypt` or by `encryptAnonymously`.
     *
     * Which of the two it was is reported as `DecryptedEnvelope::type`, and that decides what the result's
     * `authorPubKey` is worth: `ENVELOPE_FROM_MEMBER` means the signature was verified and the author is who
     * it says; `ENVELOPE_ANONYMOUS` means the sender is unknown and `authorPubKey` is empty. Branch on the
     * type, not on the field being non-empty.
     *
     * A file envelope is not accepted here — open one with `beginFileDecryption`.
     *
     * @param envelope envelope to open
     * @return the content, and what could be established about its author
     */
    DecryptedEnvelope decrypt(const Envelope& envelope);

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
     * A handle must not be driven from two threads at once.
     *
     * @param groupId ID of the Group to seal for
     * @param size total size of the plaintext file, in bytes
     * @return handle to seal file data with
     */
    FileHandle beginFileEncryption(const GroupId& groupId, const FileSize size);

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
        const GroupId& groupId,
        const PubKey& groupPubKey,
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

private:
    GroupApi(const std::shared_ptr<GroupApiImpl>& impl);
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPI_HPP_
