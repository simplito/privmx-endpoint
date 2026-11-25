#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>

#include "privmx/endpoint/core/ContainerBaseApi.hpp"
#include "privmx/endpoint/core/LocalSeal.hpp"
#include "privmx/endpoint/core/PinStoreInterface.hpp"
#include "privmx/endpoint/group/CommitEngine.hpp"
#include "privmx/endpoint/group/DeferredWork.hpp"
#include "privmx/endpoint/group/GroupApi.hpp"
#include "privmx/endpoint/group/GroupKeys.hpp"
#include "privmx/endpoint/group/GroupMetadata.hpp"
#include "privmx/endpoint/group/GroupOperations.hpp"
#include "privmx/endpoint/group/GroupTypes.hpp"
#include "privmx/endpoint/group/ServerApi.hpp"
#include "privmx/endpoint/group/SubscriberImpl.hpp"
#include "privmx/endpoint/group/encryptors/envelope/GroupEnvelopeEncryptor.hpp"
#include "privmx/endpoint/group/encryptors/envelope/GroupEnvelopeFiles.hpp"
#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaMapper.hpp"
#include "privmx/endpoint/group/keytree/TreeCommits.hpp"
#include "privmx/endpoint/group/keytree/TreeVerifier.hpp"
#include <privmx/utils/ThreadSaveMap.hpp>

namespace privmx {
namespace endpoint {
namespace group {

class GroupApiImpl : protected core::ContainerBaseApi {
public:
    GroupApiImpl(
        const privfs::RpcGateway::Ptr& gateway,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::string& host,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
        const core::Connection& connection
    );
    ~GroupApiImpl();

    std::string createGroup(
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies,
        const std::optional<core::Buffer>& idSeed = std::nullopt,
        const std::string& visibleTo = "members"
    );
    // The resourceId a group created with `idSeed` is named by: 64 hex digits, a digest of the seed under a label
    // of its own, so a seed is never some other digest the application already publishes.
    static std::string resourceIdOfSeed(const core::Buffer& idSeed);
    static std::string deriveGroupId(const std::string& contextId, const core::Buffer& idSeed);
    std::vector<GroupResult> getGroups(const std::vector<std::string>& groupIds);
    GroupPublicKey getGroupPublicKey(const std::string& contextId, const std::string& groupId);
    void setGroupVisibility(const std::string& groupId, const std::string& visibleTo);

    void addGroupMembers(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers);

    // Both return the group's epoch after the call.
    int64_t removeGroupMembers(const std::string& groupId, const std::vector<std::string>& userIds);

    int64_t rotateGroupKey(const std::string& groupId);
    int64_t reseatGroupMembers(const std::string& groupId, const std::vector<std::string>& userIds);
    void setGroupRoles(const std::string& groupId, const std::vector<GroupRoleChange>& changes);
    void updateGroupRules(const std::string& groupId, const GroupRulesUpdate& rules);
    core::PagingList<GroupLogEntry> getGroupLog(const std::string& groupId, const core::PagingQuery& pagingQuery);
    bool renewLeaf(const std::string& groupId, const std::string& previousUserPrivKey);
    // After Connection::renewIdentity: the caller's own leaf of `groupId` re-wrapped with a previous identity key
    // where the current one does not open it. Tried once per group by this GroupApi, before its first read of the
    // group; a failure is logged and leaves the read to fail as it would have (renewLeaf remains).
    void renewOwnLeafOnce(const std::string& groupId);

    // The pins the PinStore holds for `previous` (an earlier identity key of this user), taken only for groups
    // with no pin under the current key (never replacing or raising one) and saved under the current key. No store,
    // the current key, or adopted already: nothing. Throws core::LocalStateIntegrityException when the previous
    // key's stored pins do not open (nothing adopted), and what the store throws.
    void adoptPreviousIdentity(const privmx::crypto::PrivateKey& previous);

    void updateGroupPublicMeta(const std::string& groupId, const core::Buffer& publicMeta, const int64_t version);
    void updateGroupPrivateMeta(const std::string& groupId, const core::Buffer& privateMeta, const int64_t version);
    void updateGroupPolicy(const std::string& groupId, const core::ContainerPolicy& policies);
    void deleteGroup(const std::string& groupId);

    Group getGroup(const std::string& groupId);
    core::PagingList<GroupSummary> listGroups(const std::string& contextId, const core::PagingQuery& pagingQuery);

    std::unordered_map<std::string, core::GroupEpochInfo> fetchGroupEpochs(
        const std::string& contextId,
        const std::vector<std::string>& groupIds
    );

    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);
    std::string buildSubscriptionQuery(
        EventType eventType,
        EventSelectorType selectorType,
        const std::string& selectorId
    );
    std::string buildCustomEventSubscriptionQuery(
        const std::string& channelName,
        EventSelectorType selectorType,
        const std::string& selectorId
    );
    // See `GroupKeys::resolveGroupPrivKey`.
    privmx::crypto::PrivateKey resolveGroupPrivKey(
        const std::string& groupId,
        int64_t epoch = 0,
        const VerifiedGroup* seatedRead = nullptr,
        const ClimbWith* with = nullptr
    );

    void sendCustomEvent(
        const std::string& groupId,
        const std::string& channelName,
        const core::Buffer& eventData,
        const std::vector<std::string>& users
    );

    // -- envelopes. `location` is a path, or `noLocation()`; see GroupApi.hpp for what each call promises. ------

    // The one Path that stands for "bound to no location": a single identifier segment with no bytes, which no
    // real path can contain.
    static Path noLocation();
    // One spelling per identifier: a UUID in one of its exact forms (32 hex digits, 8-4-4-4-12, that in braces; any
    // case) becomes a tag byte and its 16 bytes; anything else a different tag byte and its bytes as given.
    static core::Buffer idFromString(const std::string& identifier);
    static EnvelopeHeader peekEnvelope(const core::Buffer& envelope);

    Envelope encrypt(
        const std::string& groupId,
        const Path& location,
        const core::Buffer& content,
        const EncryptOptions& options
    );
    DecryptedEnvelope decrypt(
        const std::string& groupId,
        const Path& location,
        const Envelope& envelope,
        const DecryptOptions& options,
        EnvelopeContent content = EnvelopeContent::Message
    );
    std::vector<DecryptResult> decryptMany(const std::string& groupId, const std::vector<DecryptItem>& items);
    Envelope encryptAsOutsider(
        const std::string& contextId,
        const std::string& groupId,
        const Path& location,
        const core::Buffer& content,
        const EncryptOptions& options
    );
    Envelope encryptAnonymously(
        const std::string& groupId,
        const std::string& groupPubKey,
        const Path& location,
        const core::Buffer& content
    );
    DecryptedOutsiderEnvelope decryptFromOutsider(
        const std::string& groupId,
        const Path& location,
        const Envelope& envelope,
        const DecryptOptions& options,
        EnvelopeContent content = EnvelopeContent::Message
    );
    DecryptedAnonymousEnvelope decryptAnonymous(
        const std::string& groupId,
        const Path& location,
        const Envelope& envelope,
        EnvelopeContent content = EnvelopeContent::Message
    );
    DecryptedSharedEnvelope decryptShared(
        const std::string& contextId,
        const Path& location,
        const Envelope& envelope,
        const DecryptOptions& options,
        EnvelopeContent content = EnvelopeContent::Message
    );

    FileHandle beginFileEncryption(const std::string& groupId, const Path& location, const EncryptOptions& options);
    FileHandle beginFileEncryptionAsOutsider(
        const std::string& contextId,
        const std::string& groupId,
        const Path& location,
        const EncryptOptions& options
    );
    FileHandle beginFileEncryptionAnonymously(
        const std::string& groupId,
        const std::string& groupPubKey,
        const Path& location
    );
    core::Buffer encryptFileChunk(FileHandle fileHandle, const core::Buffer& plainChunk);
    Envelope finishFileEncryption(FileHandle fileHandle);
    void abortFile(FileHandle fileHandle);
    FileHandle beginFileDecryption(
        const std::string& groupId,
        const Path& location,
        const Envelope& envelope,
        const DecryptOptions& options
    );
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
    core::Buffer decryptFileChunk(FileHandle fileHandle, const core::Buffer& cipherChunk);
    CipherRange getFileCipherRange(FileHandle fileHandle, FilePosition from, FilePosition to);
    CipherOffset seekInEncryptedFile(FileHandle fileHandle, FilePosition position);
    DecryptedFileInfo finishFileDecryption(FileHandle fileHandle);

    SequenceHandle beginSequence(const std::string& groupId, const Path& location, int64_t checkpointEvery);
    core::Buffer getSequenceHeader(SequenceHandle sequence);
    SequenceAppendResult appendToSequence(SequenceHandle sequence, const core::Buffer& data);
    core::Buffer checkpointSequence(SequenceHandle sequence);
    core::Buffer finishSequence(SequenceHandle sequence);
    SequenceHandle openSequence(
        const std::string& groupId,
        const Path& location,
        const core::Buffer& header,
        const DecryptOptions& options,
        const std::optional<core::Buffer>& resumeFrom
    );
    SequenceItem readSequenceItem(SequenceHandle sequence, const core::Buffer& item);
    SequenceMarkInfo verifySequenceMark(SequenceHandle sequence, const core::Buffer& mark);
    void closeSequence(SequenceHandle sequence);
    static SequenceItemHeader peekSequenceItem(const core::Buffer& itemOrMark);

    // -- spaces: GroupApiImplSpaces.cpp --
    std::string createSpace(
        const std::string& contextId,
        const std::vector<SpaceRecipient>& recipients,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<core::Buffer>& idSeed
    );
    static std::string deriveSpaceId(const std::string& contextId, const core::Buffer& idSeed);
    SpaceState getSpace(const std::string& spaceId);
    core::PagingList<SpaceState> listSpaces(const std::string& contextId, const core::PagingQuery& pagingQuery);
    void deleteSpace(const std::string& spaceId);
    void addSpaceRecipients(const std::string& spaceId, const std::vector<SpaceRecipient>& recipients);
    int64_t removeSpaceRecipients(const std::string& spaceId, const std::vector<SpaceRecipientRef>& recipients);
    int64_t rotateSpaceKey(const std::string& spaceId);
    void updateSpacePublicMeta(const std::string& spaceId, const core::Buffer& meta, int64_t version);
    void updateSpacePrivateMeta(const std::string& spaceId, const core::Buffer& meta, int64_t version);
    core::Buffer encryptInSpace(const std::string& spaceId, const Path& location, const core::Buffer& data);
    DecryptedSpaceEnvelope decryptInSpace(
        const std::string& spaceId,
        const Path& location,
        const core::Buffer& envelope,
        const DecryptOptions& options,
        EnvelopeContent content = EnvelopeContent::Message
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
    SequenceHandle beginSequenceInSpace(const std::string& spaceId, const Path& location, int64_t checkpointEvery);
    SequenceHandle openSequenceInSpace(
        const std::string& spaceId,
        const Path& location,
        const core::Buffer& header,
        const DecryptOptions& options,
        const std::optional<core::Buffer>& resumeFrom
    );
    SpaceOrigin getSpaceSequenceOrigin(SequenceHandle sequence);

    // The group's own route to its head entry's key must be at the answer's (verified) `keyVersion`: a key from an
    // earlier epoch is one a member removed since still holds. Throws GroupDataIntegrityException.
    static void assertHeadKeyAtEpoch(const server::GroupInfo& group);

    // The epoch of the newest state verified (or committed) for the group, 0 if none.
    std::uint64_t pinnedKeyVersion(const std::string& groupId);

    // See `TreeVerifier::agreesWithPin`.
    bool agreesWithPin(
        const std::string& groupId,
        const std::string& contextId,
        std::int64_t keyVersion,
        const std::string& groupPubKey
    );

private:
    void processNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    void processConnectedEvent();
    void processDisconnectedEvent();
    virtual std::pair<core::ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string moduleId) override;
    // Every read a key is chosen or cached from: the tree (path view), the head key's epoch and the roster
    // attestation, all on this one answer. Throws for a caller without a verifiable seat.
    VerifiedGroup readGroupForKeys(const std::string& groupId);
    // The key new envelopes are sealed under, re-read once if the cached head is behind the pinned epoch.
    core::DecryptedEncKeyV2 currentEncKey(const std::string& groupId);
    core::ModuleKeys groupToModuleKeys(const server::GroupInfo& group);

    std::map<std::string, std::string> resolveMemberKeys(
        const std::string& contextId,
        const std::vector<std::string>& userIds
    );

    // Whether a group carries the grant key its latest statement vouches for, at or past the state this process
    // verified (TreeVerifier::verifyListed). A failure is logged, not thrown.
    bool hasVerifiedGrantKey(const server::GroupInfo& group);

    // This instance's reads, pin saves and container base, for the units below.
    GroupApiHooks bindHooks();

    inline static const std::string RENEW_LEAF_OP = keytree::TreeCommits::opKey("renewLeaf");
    // Refills the blank nodes of the caller's own keyed path. A failure leaves the tree as it was; one lost to a
    // concurrent commit (`isRetryableCommitRejection`) is rescheduled, up to MAX_SELF_UPDATE_ATTEMPTS in all.
    void selfUpdate(const std::string& groupId);
    // The flush point, at the end of a public call on `groupId` that succeeded: runs the group's due deferred work
    // (`DeferredWork::run`), then `savePinsIfDue`. Best-effort: failures are logged, never thrown. Key
    // resolution for containers only records work; nothing commits there.
    void runDueWork(const std::string& groupId);
    // Saves the pins when a major move is marked, or a minor one and PIN_SAVE_IDLE_INTERVAL has passed since the last
    // save. Never throws. Runs at the end of every verifying path (`SaveDuePins`), container key lookups included, so
    // persisting rollback protection never waits for a GroupApi call.
    void savePinsIfDue() noexcept;
    struct SaveDuePins {
        GroupApiImpl& api;
        ~SaveDuePins() { api.savePinsIfDue(); }
    };

    // `GroupKeys::encKeyById` over this instance's module keys and resolver.
    core::DecryptedEncKeyV2 encKeyById(
        const std::string& groupId,
        const std::string& keyId,
        std::int64_t* epochOut = nullptr
    );

    // What the last verified read of a group said about who is in it. Kept beside the module-key cache and
    // refreshed with it, so reading an envelope's author does not cost a `groupGet` each time.
    struct RosterView {
        std::string contextId;
        std::int64_t keyVersion = 0;
        std::int64_t rosterVersion = 0;
        std::vector<std::string> users;
        std::vector<std::string> managers;
        // "manager", "user", or "" for someone who is not in the group.
        std::string roleOf(const std::string& userId) const;
    };
    RosterView rosterOf(const std::string& groupId);
    static server::GroupInfo listedFrom(const server::GroupPublicInfo& info);
    // The only writer of `_rosters`: called wherever the module-key cache is filled from a verified read.
    void rememberRoster(const server::GroupInfo& group);
    // The only way this class drops a group's cached keys: the roster goes with them.
    void dropCachedGroup(const std::optional<std::string>& groupId = std::nullopt);

    static EnvelopeBinding bindingOf(const Path& location, EnvelopeContent content = EnvelopeContent::Message);
    // "member", "outsider", "anonymous" or "shared", as GroupErrorDetails::envelopeKind names them.
    static std::string kindOf(const EnvelopeRouting& routing);
    static EnvelopeAudience audienceOf(const std::vector<WireRecipient>& recipients);
    static void requireAuthorStated(const DecryptOptions& options);
    // The envelope must name `groupId` and be of `kind`, or the call throws before any key is looked up.
    static void requireFor(const EnvelopeRouting& routing, const std::string& groupId, EnvelopeType kind);
    // `alsoFor` resolved to the keys the content key is wrapped to: each group's current verified key, each
    // user's key once the UserVerifier accepted it.
    std::vector<WireRecipient> wireRecipients(
        const std::string& contextId,
        const std::string& homeGroupId,
        const std::vector<EnvelopeRecipient>& alsoFor
    );
    // The writer named in a signed envelope, checked: it is the expected one, and the UserVerifier accepts the
    // signing key for that user.
    void requireVerifiedWriter(
        const std::string& contextId,
        const OpenedEnvelope& opened,
        const DecryptOptions& options
    );
    // The key new member envelopes are sealed with, and everything signed beside the content.
    Envelope sealAsMember(
        const std::string& groupId,
        const EnvelopeBinding& binding,
        const core::Buffer& content,
        const std::vector<EnvelopeRecipient>& alsoFor
    );
    void requireCurrentKey(const std::string& groupId, const std::string& keyId);

    ServerApi _serverApi;
    SubscriberImpl _subscriber;

    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    std::shared_ptr<GroupDataSchemaMapper> _groupDataSchemaMapper;
    keytree::TreeVerifier _treeVerifier;
    GroupEnvelopeEncryptor _envelopeEncryptor;
    // Open file handles, dropped with the sessions' keys on connect and disconnect.
    GroupEnvelopeFiles _envelopeFiles{_envelopeEncryptor, _connection};

    Envelope sealAsOutsider(
        const std::string& contextId,
        const std::string& groupId,
        const EnvelopeBinding& binding,
        const core::Buffer& content,
        const std::vector<EnvelopeRecipient>& alsoFor
    );
    FileHandle beginFileWrite(std::function<core::Buffer(const core::Buffer&)> seal);
    FileHandle beginFileRead(const core::Buffer& manifest, DecryptedFileInfo info);

    // One open sequence. Every call on the handle holds `mutex` for its whole duration.
    struct Sequence {
        std::mutex mutex;
        bool reading = false;
        bool closed = false;
        std::string id{};  // raw
        std::string key{}; // 32 bytes; every member of the epoch can learn it from the header
        std::string transcript{};
        std::uint64_t next = 0; // the position the next item written takes, or the next one read should have
        // Write side.
        core::Buffer header{};
        std::int64_t checkpointEvery = 0;
        std::int64_t sinceMark = 0;
        std::function<void()> requireCurrentEpoch{}; // throws once the sequence's epoch is over
        // Read side.
        std::string authorPubKey{};
        std::optional<SpaceOrigin> spaceOrigin{}; // a sequence read from a Space
        bool gap = false;          // an item since the last mark never arrived: the transcript cannot be checked
        std::uint64_t inOrder = 0; // the position after the last item read with no gap before it
        std::uint64_t attested = 0;
    };
    SequenceHandle openSequenceHandle(const std::string& label, std::shared_ptr<Sequence> sequence);
    // The two halves every sequence shares, whatever seals its header. `sealHeader` gets the new sequence key;
    // `requireCurrentEpoch` gets the header it returned and throws once the sequence must not go on.
    SequenceHandle beginSequenceOver(
        const std::function<core::Buffer(const core::Buffer& key)>& sealHeader,
        const std::function<std::function<void()>(const core::Buffer& header)>& epochGuard,
        int64_t checkpointEvery
    );
    SequenceHandle openSequenceOver(
        const core::Buffer& header,
        const core::Buffer& key,
        const std::string& authorPubKey,
        const std::optional<core::Buffer>& resumeFrom,
        std::optional<SpaceOrigin> spaceOrigin = std::nullopt
    );

    // -- spaces --
    // A Space as the Bridge serves it, kept for a moment: writes are frequent and each needs the current key
    // version and whether it is stale.
    // ponytail: a time bound instead of events. A stale key is noticed up to SPACE_CACHE_MS late by a writer that
    // made no change itself; subscribe to the Space's events and drop the entry on them if that window matters.
    static constexpr std::int64_t SPACE_CACHE_MS = 5000;
    struct CachedSpace {
        server::SpaceInfo info;
        std::int64_t readAt = 0;
        bool allVersions = false; // read with spaceGet: `info.keys` holds every version the caller can open
    };
    struct SpaceKeyUse {
        std::string key{};
        std::string via{}; // the recipient group the caller holds the key through; empty for the caller's own entry
    };
    struct SpaceTarget {
        bool isGroup = false;
        std::string id{};
        std::string pubKey{}; // base58-DER
        std::int64_t groupKeyVersion = 0;
    };
    server::SpaceInfo spaceInfo(const std::string& spaceId, bool fresh = false);
    void forgetSpace(const std::string& spaceId);
    void requireNoKeyRollback(const server::SpaceInfo& space);
    SpaceKeyUse spaceKeyAt(const server::SpaceInfo& space, std::int64_t keyVersion);
    // The recipients' current keys, each verified: a group's off its latest statement, a user's by the UserVerifier.
    std::vector<SpaceTarget> spaceTargets(
        const std::string& contextId,
        const std::vector<std::string>& groupIds,
        const std::vector<core::UserWithPubKey>& users
    );
    std::vector<server::SpaceKeyEntry> wrapSpaceKeyFor(
        const std::string& spaceId,
        const std::string& contextId,
        std::int64_t keyVersion,
        const std::string& spaceKey,
        const std::vector<SpaceTarget>& targets
    );
    std::int64_t replaceSpaceKey(
        const std::string& spaceId,
        const std::vector<std::string>& withoutGroups,
        const std::vector<std::string>& withoutUsers
    );
    core::Buffer sealInSpace(const std::string& spaceId, const EnvelopeBinding& binding, const core::Buffer& content);
    SpaceState toSpaceState(const server::SpaceInfo& space);
    privmx::utils::ThreadSaveMap<std::string, CachedSpace> _spaces;
    // The highest key version each Space was seen at. Not dropped on a reconnect: it only ever moves forward.
    std::mutex _spaceKeyVersionsMutex;
    std::map<std::string, std::int64_t> _spaceKeyVersions;             // guarded by the mutex above
    privmx::utils::ThreadSaveMap<std::string, SpaceKeyUse> _spaceKeys; // by "<spaceId>:<keyVersion>"
    std::shared_ptr<Sequence> sequenceOf(SequenceHandle handle, bool wantReading);
    core::Buffer markSequence(Sequence& sequence, bool closed);
    privmx::utils::ThreadSaveMap<int64_t, std::shared_ptr<Sequence>> _sequences;
    // Every group's keys, commit state and pending work.
    GroupSessions _sessions;
    std::mutex _leafRenewalMutex;
    std::set<std::string> _leafRenewalTried; // under _leafRenewalMutex
    GroupApiHooks _hooks{bindHooks()};
    GroupDeps _deps{_serverApi, _treeVerifier, _connection, _sessions, _userPrivKey, _hooks};
    DeferredWork _deferred{_deps};
    GroupKeys _keys{_deps, _deferred};
    CommitEngine _engine{_deps};
    GroupMetadata _metadata{_deps, *_groupDataSchemaMapper, _keyProvider, _keys};
    GroupOperations _ops{
        _deps, *_groupDataSchemaMapper, _keyProvider, _groupPrivKeyResolver, _keys, _deferred, _metadata, _engine
    };
    bool _dueWorkOff = false; // tests: `runDueWork` does nothing
    privmx::utils::ThreadSaveMap<std::string, RosterView> _rosters;

    // Lock order: GroupSession::commitMutex -> _pinSaveMutex -> _pinsMovedMutex. _pinsMovedMutex is a leaf, like
    // GroupSession::mutex and DeferredWork's lock (see CommitEngine and DeferredWork).

    // Pins kept in the connection's PinStore, shared by every GroupApi of this identity on this Bridge.
    // `loadPins` merges the slot into memory once, at construction; `savePins` merges memory into the slot
    // (compare-and-swap, `PinBlob::higher`) and the result back into memory. `pinsMoved` only marks them; saves run
    // after every own commit but a self-update before the call returns, in `runDueWork` (a major move at once, minor
    // ones once PIN_SAVE_IDLE_INTERVAL has passed since the last save) and at the end of every verification
    // (`SaveDuePins`), on disconnect and in the destructor. A failed
    // save is logged and retried in full like a minor move; the pins in memory keep protecting this instance meanwhile.
    void loadPins();
    void pinsMoved(bool major);
    bool savePins(bool all = false);
    // The one place this instance's slot, identity, label and version are named together.
    core::LocalSeal pinSeal() const;
    // The adoption itself (`adoptPreviousIdentity`, and the bodies `ConnectionImpl::adoptPreviousIdentity` staged).
    void adoptBody(const keytree::TreeVerifier::PinSet& adopted);

    // 30 s for self-update-only moves.
    static constexpr std::chrono::milliseconds PIN_SAVE_IDLE_INTERVAL{30000};

    std::shared_ptr<core::PinStoreInterface> _pinStore; // set once, in the constructor
    std::string _pinStoreKey;
    std::mutex _pinSaveMutex; // serialises saves; guards the two below
    bool _pinSaveFull = false;
    std::set<std::string> _adoptedIdentities;
    // Under `_pinsMovedMutex`: moved since the last save (a major move among them), and when the last save was tried.
    std::mutex _pinsMovedMutex;
    bool _pinsMoved = false;
    bool _pinsMovedMajor = false;
    std::chrono::steady_clock::time_point _lastPinSave;
    friend struct GroupApiImplTestAccess; // tests reach selfUpdate() and turn `runDueWork` off
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_
