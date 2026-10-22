#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>

#include "privmx/endpoint/core/ContainerBaseApi.hpp"
#include "privmx/endpoint/core/PinStoreInterface.hpp"
#include "privmx/endpoint/group/GroupApi.hpp"
#include "privmx/endpoint/group/GroupTypes.hpp"
#include "privmx/endpoint/group/ServerApi.hpp"
#include "privmx/endpoint/group/SubscriberImpl.hpp"
#include "privmx/endpoint/group/encryptors/envelope/GroupEnvelopeEncryptor.hpp"
#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaMapper.hpp"
#include "privmx/endpoint/group/keytree/GroupKeyResolver.hpp"
#include "privmx/endpoint/group/keytree/TreeCommits.hpp"
#include "privmx/endpoint/group/keytree/TreeKeyCache.hpp"
#include "privmx/endpoint/group/keytree/TreeKeyCacheRegistry.hpp"
#include "privmx/endpoint/group/keytree/TreeVerifier.hpp"
#include <privmx/utils/PrivmxException.hpp>
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

    // m2: how long a released statement with no known outcome holds back a different one at its prevDigest. An honest
    // bridge refuses a statement dated more than DATE_TOLERANCE_MS behind its clock; twice that covers both clocks.
    static constexpr std::uint64_t RELEASE_WINDOW_MS = 2 * keytree::TreeCommits::DATE_TOLERANCE_MS;

    std::string createGroup(
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies
    );

    void addGroupMembers(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers);

    void removeGroupMembers(const std::string& groupId, const std::vector<std::string>& userIds);

    void rotateGroupKey(const std::string& groupId);
    bool renewLeaf(const std::string& groupId, const std::string& previousUserPrivKey);

    // 01: the pins the PinStore holds for `previous` (an earlier identity key of this user), taken only for groups
    // with no pin under the current key (never replacing or raising one) and saved under the current key. No store,
    // the current key, or adopted already: nothing. Throws core::LocalStateIntegrityException when the previous
    // key's stored pins do not open (nothing adopted), and what the store throws.
    void adoptPreviousIdentity(const privmx::crypto::PrivateKey& previous);

    // Which planes a carry-forward moves: after a removal or rotation, the planes behind the new epoch (or, with
    // history abandoned, starts them over empty); after a narrowing policy commit, the planes whose author lost
    // `update` (`losers`).
    enum class CarryScope { Removal, Policy };

    // Called after a removal, rotation or narrowing commits, never as part of it: best-effort, re-signing under the
    // committer's name only an entry identical to the one it read before its own commit (N-2) whose author held
    // `update` under that read's rules and roster (`prior`, T4-03). Returns whether nothing is left to carry.
    bool carryMetadataForward(
        const std::string& groupId,
        CarryScope scope,
        bool historyAbandoned,
        const std::vector<std::string>& losers,
        const PriorRole& prior
    );

    // A narrowing's carry-forward still to do: the planes' authors who lost `update`, and the read before it.
    struct PendingCarry {
        std::vector<std::string> losers;
        PriorRole prior;
    };

    void updateGroupPublicMeta(
        const std::string& groupId,
        const core::Buffer& publicMeta,
        const int64_t version
    );
    void updateGroupPrivateMeta(
        const std::string& groupId,
        const core::Buffer& privateMeta,
        const int64_t version
    );
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
    // `seatedRead`: a read of this group the caller has already verified (`verifyTree`, seated). Its own current
    // epoch then resolves off it rather than off a second read that would verify the same thing again.
    // `with`: climb with another key over another cache (leaf renewal); nothing then reaches `_epochKeys`, the
    // group's shared cache or the background queue.
    struct ClimbWith {
        std::shared_ptr<keytree::TreeKeyCache> cache;
        const privmx::crypto::PrivateKey* key;
    };
    privmx::crypto::PrivateKey resolveGroupPrivKey(
        const std::string& groupId,
        int64_t epoch = 0,
        const server::GroupInfo* seatedRead = nullptr,
        const ClimbWith* with = nullptr
    );

    void sendCustomEvent(
        const std::string& groupId,
        const std::string& channelName,
        const core::Buffer& eventData,
        const std::vector<std::string>& users
    );

    Envelope encrypt(const std::string& groupId, const core::Buffer& content);
    DecryptedEnvelope decrypt(const Envelope& envelope);
    Envelope encryptAnonymously(
        const std::string& groupId,
        const std::string& groupPubKey,
        const core::Buffer& content
    );

    FileHandle beginFileEncryption(const std::string& groupId, FileSize size);
    FileHandle beginFileEncryptionAnonymously(
        const std::string& groupId,
        const std::string& groupPubKey,
        FileSize size
    );
    core::Buffer encryptFileChunk(FileHandle fileHandle, const core::Buffer& plainChunk);
    FileHandle beginFileDecryption(const Envelope& envelope);
    core::Buffer decryptFileChunk(FileHandle fileHandle, const core::Buffer& cipherChunk);
    CipherOffset seekInEncryptedFile(FileHandle fileHandle, FilePosition position);
    Envelope finishFileEncryption(FileHandle fileHandle);
    DecryptedFileInfo finishFileDecryption(FileHandle fileHandle);

    // Narrowing the archive first keeps the key provider to one grant-key resolution per envelope opened,
    // rather than one per key the group has ever held. Only the group's own routes: its key is wrapped to itself.
    static std::vector<core::server::GroupKeysEntry> filterToKeyId(
        const std::vector<core::server::GroupKeysEntry>& all,
        const std::string& groupId,
        const std::string& keyId
    );

    // Whether `wrappedBy` opened the epoch one of `routes` labels the key with (the group's creator or a remover,
    // the only members who wrap an epoch's content key). Anybody in the context can wrap a key of their own to an
    // epoch's public grant key; the opener, after `epochOpeners`, is a member's signed word.
    static bool wrappedByEpochOpener(
        const std::vector<core::server::GroupKeysEntry>& routes,
        const std::string& wrappedBy,
        const std::map<std::uint64_t, keytree::CommitStatement>& openers
    );

    static std::string describeResolveFailure(const keytree::ResolveResult& resolved);

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

    // The ladder between the two epochs, as the group's statements vouch for it (GroupKeyResolver::authenticated).
    // `group` must have passed `verifyTree`, which pins it.
    server::GroupGetKeyArchiveResult fetchKeyArchive(
        const server::GroupInfo& group,
        int64_t targetEpoch,
        int64_t currentEpoch
    );

    // The group's session key cache. Internal, for tests that need to plant a wrong key (a client bug) in it.
    std::shared_ptr<keytree::TreeKeyCache> keyCacheOf(const std::string& groupId);

private:
    void processNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    void processConnectedEvent();
    void processDisconnectedEvent();
    virtual std::pair<core::ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string moduleId) override;
    // Every read a key is chosen or cached from: the tree (path view), the head key's epoch and the roster
    // attestation, all on this one answer. Throws for a caller without a verifiable seat.
    server::GroupInfo readGroupForKeys(const std::string& groupId);
    // The group key resolver; with `seatedRead`, serving its current epoch off it (see `resolveGroupPrivKey`).
    core::KeyProvider::GroupPrivKeyResolver resolverOver(
        const server::GroupInfo* seatedRead,
        const ClimbWith* with = nullptr
    );
    // The key new envelopes are sealed under, re-read once if the cached head is behind the pinned epoch.
    core::DecryptedEncKeyV2 currentEncKey(const std::string& groupId);
    core::ModuleKeys groupToModuleKeys(const server::GroupInfo& group);

    static std::vector<keytree::TreeMember> toTreeMembers(
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers
    );

    // `rosterTag` has to be computed over exactly the fields the block declares. One builder for all three
    // roster writers, so the tag inputs and the declared values cannot drift apart.
    static dynamic::MembershipBlock buildMembershipBlock(
        const core::EncKey& key,
        const std::string& groupPubKey,
        int64_t keyVersion,
        int64_t rosterVersion,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers
    );

    static RosterAfterChange rosterFromUserIds(
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers
    );

    // The entire shared prologue of both metadata writes; neither plane reads the other's envelope.
    // Kept in one place so the epoch guard cannot drift between the two callers.
    // `currentGroup` comes from `readGroupForKeys`.
    MetaWriteContext prepareMetaWrite(const server::GroupInfo& currentGroup);
    void writePublicMeta(const server::GroupInfo& currentGroup, const core::Buffer& publicMeta, int64_t version);
    void writePrivateMeta(const server::GroupInfo& currentGroup, const core::Buffer& privateMeta, int64_t version);

    std::map<std::string, std::string> resolveMemberKeys(
        const std::string& contextId,
        const std::vector<std::string>& userIds
    );

    // The long-term keys a commit wraps to: the caller's own from its key, newcomers' from the arguments (left out
    // here), everybody else's from the Context user list.
    std::map<std::string, std::string> commitRecipientKeys(
        const server::GroupInfo& group,
        const std::vector<std::string>& recipients,
        const std::string& ownUserId,
        const std::set<std::string>& newcomers = {}
    );

    // Checks the served tree against the commit statements before any key from it is used (TreeVerifier). Returns
    // false, checking nothing, for a group without a supported tree or a caller without a seat: there is nothing it
    // could climb, and the caller refuses both. Any failure is re-read (`model`) once into `group` and checked
    // again: a torn read, or a concurrent read having pinned a newer state, passes the second time.
    bool verifyTree(server::GroupInfo& group, const server::GroupGetModel& model, keytree::TreeVerifier::Scope scope);
    // The read after `settle` completed an earlier commit (Settled::Reread). The read before it verified, so this
    // one must too: a commit is never planned or signed on an answer nobody checked.
    server::GroupInfo rereadVerified(const server::GroupGetModel& model, keytree::TreeVerifier::Scope scope);

    // Whether a group carries the grant key its latest statement vouches for, at or past the state this process
    // verified (TreeVerifier::verifyListed). A failure is logged, not thrown.
    bool hasVerifiedGrantKey(const server::GroupInfo& group);

    // The connection's UserVerifier and the group's statements, as TreeVerifier reads them.
    keytree::TreeVerifier::Environment treeEnvironment(const std::string& groupId);

    // Client time a commit statement is signed at, in milliseconds.
    static std::uint64_t commitDate();

    // Chains an unsigned statement to `group`'s latest (verified) one: its digest as `prevDigest`, and a date no
    // earlier than its, which readers require of the chain. Refused at a seq a statement of ours was refused at as a
    // lost race (T4-17): that one may have been applied, and a second one there would be a fork.
    void chainTo(keytree::CommitStatement& statement, const server::GroupInfo& group);
    // The served group's signed rules, which a verified read bound to its latest statement (`describes`).
    static keytree::GroupRules rulesOf(const server::GroupInfo& group);
    // `carry` is set when the change narrows `update` under a plane's author (commit B).
    void updateGroupPolicyOnce(
        const std::string& groupId,
        const core::ContainerPolicy& policies,
        std::optional<PendingCarry>& carry
    );

    // m2: a commit released to the bridge with no known outcome. A retry of the same operation resends exactly this
    // (no second statement, no wasted epoch); any other operation drops it after one resend and plans afresh (13: the
    // hold that refused other operations is gone, the fork it closed is one a bridge can reach by withholding).
    struct UnresolvedCommit {
        std::string digest; // of the released statement (set by `submit`)
        std::uint64_t seq = 0;  // its seq (set by `submit`)
        std::uint64_t date = 0; // its signed date (set by `submit`)
        std::string op;     // keytree::TreeCommits::opKey of what the caller asked for
        // The op key names the state the call asks for (these members added, those removed): found landed, it is
        // Done whenever. Otherwise it names an event (a rotation), and a later call with the same key is its retry
        // only inside RELEASE_WINDOW_MS from `date`; past it, a new request.
        bool namesEndState = false;
        std::string kind;   // "add", "remove", ... for messages
        std::string contextId;
        std::vector<core::UserWithPubKey> newcomers; // add only: re-checked before every resend
        std::function<void()> send;                  // the request as first sent; never re-planned
        std::function<void()> landed;                // pin + caches once accepted; looks the TreeKeyCache up itself
        std::function<void()> after;                 // best-effort follow-up (a removal's metadata refresh) or empty
    };
    // Proceed: plan on the read. Done: the caller's own op landed (now or before). Reread: another op of this
    // client, or an earlier call of an event op past its window, was completed first; read again. Deferred: the background self-update yields to another op's commit.
    enum class Settled {
        Proceed,
        Done,
        Reread,
        Deferred
    };
    inline static const std::string SELF_UPDATE_OP = keytree::TreeCommits::opKey("selfUpdate");

    // Per group; held only from release to outcome, never across reads or the UserVerifier.
    std::shared_ptr<std::mutex> commitLock(const std::string& groupId);
    // Right after a read that verified (`verifyTree` returned true), before planning on it: completes this client's
    // unresolved commit to the group, if any (resend, or noticing it landed: the pin is exactly it). Past its window,
    // behind the pin, or failing again for another op, it is dropped and the caller plans afresh. `mayCompleteOther`:
    // whether a different op may resend it (every app op; not the background self-update).
    Settled settle(const std::string& groupId, const std::string& op, bool mayCompleteOther);
    // Sends a signed statement and keeps `commit` until its outcome is known. Throws keytree::StalePlan for a plan
    // behind the pin. A refusal as a lost race (`isRetryableCommitRejection`) is remembered for `chainTo` (T4-17).
    void submit(const std::string& groupId, const keytree::CommitStatement& statement, UnresolvedCommit commit);
    void forgetUnresolved(const std::string& groupId, const std::string& digest);

    // `group` must have passed `verifyTree` at plan scope. `removing` (a removal of these users): a climb that fails on
    // the served edges (not on membership) is logged and the state returned anyway — a removal plans from public state
    // alone; but a leaf that does not open with the session's key and climbs with a previous identity key this
    // client was given (`climbsWithPreviousIdentity`) is refused, pointing at renewLeaf, unless history stays
    // reachable: renewLeaf fixes exactly that case, and nothing else.
    // `climbKey`: climb with it instead of the session's key, and schedule no self-update off the climb.
    // Whether one of the previous identity keys (adoptPreviousIdentity, here or on the connection) climbs `state` to
    // its grant key. Climbs on a scratch cache, so nothing derived from a previous key reaches a reader.
    bool climbsWithPreviousIdentity(const keytree::TreeGroupState& state, const std::string& memberId);
    keytree::TreeGroupState climbForPlanning(
        const server::GroupInfo& group,
        const std::shared_ptr<keytree::TreeKeyCache>& cache,
        const std::vector<std::string>* removing = nullptr,
        const privmx::crypto::PrivateKey* climbKey = nullptr
    );

    // One attempt each; `commitWithRetry` re-runs them, from a fresh read, when a concurrent commit moved the base.
    void addGroupMembersOnce(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers);
    // Returns whether the removal abandoned history (the caller held no current grant key); nullopt when an
    // earlier attempt of the same removal turned out to have landed (`settle` ran its metadata refresh then).
    // `prior` is what the attempt read, for `carryMetadataForward`.
    std::optional<bool> removeGroupMembersOnce(
        const std::string& groupId,
        const std::vector<std::string>& userIds,
        PriorRole& prior
    );
    // `prior` is what the attempt read, for `carryMetadataForward`. False when an earlier attempt of a rotation turned
    // out to have landed (`settle` ran its metadata refresh then).
    bool rotateGroupKeyOnce(const std::string& groupId, PriorRole& prior);

    // The verified read's rules, roster and planes.
    static PriorRole priorOf(const server::GroupInfo& group);
    // Runs a narrowing's carry-forward; one that does not complete is kept for `retryPendingCarry`.
    void runPolicyCarry(const std::string& groupId, const PendingCarry& carry);
    void retryPendingCarry(const std::string& groupId);

    // What a commit opening a new epoch publishes beside the tree, shared by removal and rotation: the roster under a
    // fresh metadata key (a key never used before once history is abandoned), and that key wrapped once to the new
    // grant key.
    struct NewEpochRoster {
        std::string keyId;
        Poco::Dynamic::Var data;
        core::server::GroupKeyEntrySet groupKeys;
    };
    NewEpochRoster sealRosterForNewEpoch(
        const server::GroupInfo& currentGroup,
        const RosterAfterChange& roster,
        const std::string& newGroupPubKeyStr,
        int64_t newEpoch,
        int64_t newRosterVersion,
        bool abandonHistory
    );

    // After this client's commit opened `statement.keyVersion`: pins it before anything reads the group again (the
    // state it replaced is refused from then on) and keeps the new grant key, the epoch's published one. `users` /
    // `managers` are the roster the statement signed. An `UnresolvedCommit::landed`, so it takes nothing by reference.
    void adoptCommittedEpoch(
        const std::string& groupId,
        const std::string& contextId,
        const keytree::CommitStatement& statement,
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers,
        const keytree::GroupRules& rules,
        const privmx::crypto::PrivateKey& grantKey
    );

    static void commitWithRetry(const std::function<void()>& attempt);
    static bool isRetryableCommitRejection(const privmx::utils::PrivmxException& e);

    // Refills the blank nodes of the caller's own keyed path. A failure leaves the tree as it was; one lost to a
    // concurrent commit (`isRetryableCommitRejection`) is rescheduled, up to MAX_SELF_UPDATE_ATTEMPTS in all.
    void selfUpdate(const std::string& groupId);
    // A self-update; with `previousKey`, the leaf renewal: no need gates, a climb with the previous key over a
    // call-local cache, signed with the session's (new) key. False when the leaf already opens with the session's key.
    bool selfUpdateWith(
        const std::string& groupId,
        const privmx::crypto::PrivateKey* previousKey,
        const std::string& op,
        bool mayCompleteOther
    );
    inline static const std::string RENEW_LEAF_OP = keytree::TreeCommits::opKey("renewLeaf");
    // Schedules one when `group` (a seated, verified read) shows the caller's path needs it: within a window that
    // grows with the group for the seat that heals first, one window later for any other (`healsFirst`).
    void scheduleSelfUpdateIfNeeded(const std::string& groupId, const server::GroupInfo& group);
    // At most one pending or running per group, after a random delay so a group's members do not all commit at once.
    void scheduleSelfUpdate(const std::string& groupId, std::int64_t windowMs, bool healsFirst, int attempts = 0);
    void runSelfUpdates();

    // The new epoch's rungs, each checked to open with `newGrantKey` to the key the chain (never the cache) names for
    // its target before anything is submitted. On failure the offending target is forgotten, so the next attempt
    // re-gathers it by a verified descent, and GroupDataIntegrityException is thrown.
    std::vector<keytree::ArchiveRung> buildRotationRungs(
        const server::GroupInfo& group,
        std::uint32_t newEpoch,
        const privmx::crypto::PrivateKey& newGrantKey,
        const std::optional<privmx::crypto::PrivateKey>& previousEpochKey,
        const std::string& author,
        keytree::TreeKeyCache& cache
    );

    // ── Ladder repair (L-1). Every queue below is guarded by _selfUpdateMutex and served by _selfUpdateWorker. ──

    // `clamp(numLeaves·8 ms, 1 s, 120 s)`: how far a group's members spread their background work.
    static std::int64_t backgroundWindowMs(const server::GroupInfo& group);
    // Requires _selfUpdateMutex held. The earliest due time over every background source.
    std::optional<std::chrono::steady_clock::time_point> nextDue() const;
    // Requires _selfUpdateMutex held. Starts the worker if needed and wakes it; never after _selfUpdateStopping.
    void wakeBackgroundWorker();
    // Queues one check of the rungs at `at`, once per (group, epoch), after a random delay within `windowMs`.
    void scheduleLadderCheck(
        const std::string& groupId,
        const std::string& contextId,
        std::uint32_t at,
        std::int64_t windowMs
    );
    // A rotation to `cur` this session observed while holding `cur - 1`: check `cur`'s rungs, once.
    void scheduleObservedRotation(
        const std::string& groupId,
        const std::string& contextId,
        std::uint32_t cur,
        std::int64_t windowMs
    );
    // The epoch's rungs are known good (this client just checked and committed them).
    void markLadderChecked(const std::string& groupId, std::uint32_t epoch);
    // On the worker, no lock held: finds spans at `at` no rung opens and repairs those it holds both keys of,
    // after checking those keys against the chain.
    void checkLadderAt(const std::string& groupId, const std::string& contextId, std::uint32_t at);

    // Includes open file handles, not just the key caches.
    void dropEnvelopeState();

    // Every key memoized for the group (tree key cache, epoch keys, envelope keys and grant epochs): a deleted id may
    // come back as another group, whose epochs share the numbers but not the keys.
    void forgetGroupKeys(const std::string& groupId);

    // Length-prefixed `groupId`, so one pair cannot collide with another under a different split.
    static std::string memoKeyFor(const std::string& groupId, const std::string& suffix);

    // Reaches back through the whole archive, however old the key is.
    core::DecryptedEncKeyV2 encKeyById(const std::string& groupId, const std::string& keyId);

    // The sender only ever held a public key, so its epoch is recovered from the group's published history
    // rather than carried on the wire.
    privmx::crypto::PrivateKey grantKeyForPubKey(const std::string& groupId, const std::string& groupPubKeyBase58);

    std::shared_ptr<EnvelopeFile> getFileState(FileHandle fileHandle, bool wantReading);
    void releaseFileHandle(FileHandle fileHandle);
    // The caller holds the handle's lock.
    core::Buffer drainChunks(EnvelopeFileState& state);
    // Shared tail of both finishers: completeness check, then close and release whatever the outcome.
    EnvelopeFileState finishFile(FileHandle fileHandle, bool wantReading);

    ServerApi _serverApi;
    SubscriberImpl _subscriber;

    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    std::shared_ptr<GroupDataSchemaMapper> _groupDataSchemaMapper;
    keytree::TreeKeyCacheRegistry _treeKeyCaches;
    keytree::TreeVerifier _treeVerifier;
    GroupEnvelopeEncryptor _envelopeEncryptor;
    // Keys already unwrapped for envelopes, by `memoKeyFor(groupId, keyId)`; a keyId names one immutable piece
    // of key material. Dropped on connect and disconnect, so an era cut takes effect at reconnect.
    privmx::utils::ThreadSaveMap<std::string, core::DecryptedEncKeyV2> _envelopeKeys;
    // Which epoch a published grant public key belongs to, by `memoKeyFor(groupId, pubKeyBase58)`.
    privmx::utils::ThreadSaveMap<std::string, int64_t> _envelopeGrantEpochs;
    privmx::utils::ThreadSaveMap<int64_t, std::shared_ptr<EnvelopeFile>> _envelopeFiles;
    // Grant private keys by `memoKeyFor(groupId, epoch)`, each checked against the epoch's published public key.
    // Kept for the whole connection (dropped on disconnect): a removal ends a member's access to later epochs, and
    // a hot session keeps the ones it already held — as it would by keeping the keys themselves.
    privmx::utils::ThreadSaveMap<std::string, privmx::crypto::PrivateKey> _epochKeys;

    // Background self-updates run on a thread of their own rather than the shared executor: a task there waits out
    // its random delay, and a handful of groups waiting at once would hold every pool thread and stall event
    // delivery for all modules. Joined in the destructor; pending ones are dropped on disconnect.
    std::mutex _selfUpdateMutex;
    std::condition_variable _selfUpdateWake;
    struct PendingSelfUpdate {
        std::chrono::steady_clock::time_point due;
        std::int64_t windowMs; // the delay window it was scheduled with, reused by a retry
        int attempts;          // lost races so far, counted toward MAX_SELF_UPDATE_ATTEMPTS
    };
    std::map<std::string, PendingSelfUpdate> _selfUpdatePending;
    std::optional<std::string> _selfUpdateRunning;
    static constexpr int MAX_SELF_UPDATE_ATTEMPTS = 3;
    struct PendingLadderCheck {
        std::string groupId;
        std::string contextId;
        std::uint32_t at;
        std::chrono::steady_clock::time_point due;
    };
    std::map<std::string /* groupId|at */, PendingLadderCheck> _ladderChecks;
    std::map<std::string /* groupId */, std::uint32_t> _ladderCheckedAt; // highest `at` already queued or checked
    bool _selfUpdateStopping = false;
    std::thread _selfUpdateWorker;

    // m2 (A5-F3): one released statement per prevDigest. The bodies survive reconnects on purpose: a dropped
    // connection is the commonest unknown outcome, and the same call retried after it must resend, not be held back.
    std::mutex _unresolvedMutex;                                     // guards both maps
    std::map<std::string, std::shared_ptr<std::mutex>> _commitLocks; // never pruned: one per group committed to
    std::map<std::string, UnresolvedCommit> _unresolved;
    // ponytail: in memory only. A crash before the retry leaves the planes refused until a member holding `update`
    // writes metadata (documented on updateGroupPolicy); persist it next to 01's pins if that ever matters.
    std::mutex _pendingCarryMutex;
    std::map<std::string, PendingCarry> _pendingCarry;
    // 01: pins kept in the connection's PinStore, shared by every GroupApi of this identity on this Bridge.
    // `loadPins` merges the slot into memory once, at construction; `savePins` merges memory into the slot
    // (compare-and-swap, `PinBlob::higher`) and the result back into memory. Saves run on the worker (major moves
    // within PIN_SAVE_INTERVAL, minor ones within PIN_SAVE_IDLE_INTERVAL), after every own commit but a background
    // self-update before the call returns, on disconnect and in the destructor. A failed save is logged and retried in
    // full; the pins in memory keep protecting this instance meanwhile.
    void loadPins();
    void pinsMoved(bool major);
    bool savePins(bool all = false);
    // The adoption itself (`adoptPreviousIdentity`, and the bodies `ConnectionImpl::adoptPreviousIdentity` staged).
    void adoptBody(const keytree::TreeVerifier::PinSet& adopted);

    // ponytail constants: 1 s for major moves, 30 s for self-update-only moves.
    static constexpr std::chrono::milliseconds PIN_SAVE_INTERVAL{1000};
    static constexpr std::chrono::milliseconds PIN_SAVE_IDLE_INTERVAL{30000};

    std::shared_ptr<core::PinStoreInterface> _pinStore; // set once, in the constructor
    std::string _pinStoreKey;
    std::mutex _pinSaveMutex; // serialises saves; guards the two below
    bool _pinSaveFull = false;
    std::set<std::string> _adoptedIdentities;
    // The previous identity keys handed to `adoptPreviousIdentity` (renewLeaf), pins stored or not; together with
    // ConnectionImpl::previousIdentities, what `climbForPlanning` knows of an own key change.
    std::mutex _previousIdentitiesMutex;
    std::vector<privmx::crypto::PrivateKey> _previousIdentities; // under `_previousIdentitiesMutex`
    // Under `_selfUpdateMutex`: when the worker saves next, and when the last save succeeded.
    std::optional<std::chrono::steady_clock::time_point> _pinSaveDue;
    std::chrono::steady_clock::time_point _lastPinSave;
    friend struct GroupApiImplTestAccess; // tests reach selfUpdate() and stop the worker
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_
