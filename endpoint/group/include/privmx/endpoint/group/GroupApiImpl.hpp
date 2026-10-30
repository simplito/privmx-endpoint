#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
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

// A plan whose base is behind the pin (the client's own commit, or a read, moved it meanwhile). Retryable: a fresh
// read plans on the newer head. Not an endpoint exception; `commitWithRetry` and `runDueWork` handle it.
struct StalePlan : std::exception {
    const char* what() const noexcept override { return "group commit planned behind the pinned state"; }
};

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
        const std::optional<core::ContainerPolicy>& policies
    );

    void addGroupMembers(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers);

    void removeGroupMembers(const std::string& groupId, const std::vector<std::string>& userIds);

    void rotateGroupKey(const std::string& groupId);

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
    privmx::crypto::PrivateKey resolveGroupPrivKey(
        const std::string& groupId,
        int64_t epoch = 0,
        const server::GroupInfo* seatedRead = nullptr
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
    // How long a released statement with no known outcome holds back a different one at its prevDigest. An honest
    // bridge refuses a statement dated more than DATE_TOLERANCE_MS behind its clock; twice that covers both clocks.
    static constexpr std::uint64_t RELEASE_WINDOW_MS = 2 * keytree::TreeCommits::DATE_TOLERANCE_MS;

    // Which planes a carry-forward moves: after a removal or rotation, the planes behind the new epoch (or, with
    // history abandoned, starts them over empty); after a narrowing policy commit, the planes whose author lost
    // `update` (`losers`).
    enum class CarryScope { NewEpoch, Policy };

    // Called after a removal, rotation or narrowing commits, never as part of it: best-effort, re-signing under the
    // committer's name only an entry identical to the one it read before its own commit whose author held
    // `update` under that read's rules and roster (`prior`). Returns whether nothing is left to carry.
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

    // The ladder between the two epochs, as the group's statements vouch for it (GroupKeyResolver::authenticated).
    // `group` must have passed `verifyTree`, which pins it.
    server::GroupGetKeyArchiveResult fetchKeyArchive(
        const server::GroupInfo& group,
        int64_t targetEpoch,
        int64_t currentEpoch
    );
    // Only the rungs of `spans`, authenticated the same way.
    server::GroupGetKeyArchiveResult fetchKeyArchive(
        const server::GroupInfo& group,
        const std::vector<keytree::RungSpan>& spans
    );
    server::GroupGetKeyArchiveResult fetchKeyArchive(
        const server::GroupInfo& group,
        const server::GroupGetKeyArchiveModel& params
    );

    // `resolver.resolve` for an epoch below the current one, fetching as little of the ladder as it can: first the
    // canonical descent path (LadderMath::canonicalDescent), then, if a rung on it fails, the ways round the epoch it
    // stopped at (LadderMath::detourSpans), and only then the closed window `[epoch, current]` as before. Every
    // attempt is verified exactly as one over the whole window; an era boundary or a prune ends it at once.
    keytree::ResolveResult resolveDescending(
        keytree::GroupKeyResolver& resolver,
        const server::GroupInfo& group,
        int64_t epoch,
        const privmx::crypto::PrivateKey& ownKey
    );

    // Spans per `groupGetKeyArchive` call the bridge serves.
    static constexpr std::size_t MAX_ARCHIVE_SPANS = 128;
    // Rungs per page of a windowed `groupGetKeyArchive`.
    static constexpr std::size_t ARCHIVE_RUNGS_PER_PAGE = 256;

    // The group's session key cache. Internal, for tests that need to plant a wrong key (a client bug) in it.
    std::shared_ptr<keytree::TreeKeyCache> keyCacheOf(const std::string& groupId);

    void processNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    void processConnectedEvent();
    void processDisconnectedEvent();
    virtual std::pair<core::ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string moduleId) override;
    // Every read a key is chosen or cached from: the tree (path view), the head key's epoch and the roster
    // attestation, all on this one answer. Throws for a caller without a verifiable seat.
    server::GroupInfo readGroupForKeys(const std::string& groupId);
    // The group key resolver; with `seatedRead`, serving its current epoch off it (see `resolveGroupPrivKey`).
    core::KeyProvider::GroupPrivKeyResolver resolverOver(const server::GroupInfo* seatedRead);
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
    // One metadata plane (public or private) at `version + 1`, under the current epoch's key.
    void writeMeta(const server::GroupInfo& currentGroup, bool publicPlane, const core::Buffer& meta, int64_t version);

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
    // lost race: that one may have been applied, and a second one there would be a fork.
    void chainTo(keytree::CommitStatement& statement, const server::GroupInfo& group);
    // The served group's signed rules, which a verified read bound to its latest statement (`describes`).
    static keytree::GroupRules rulesOf(const server::GroupInfo& group);
    // `carry` is set when the change narrows `update` under a plane's author.
    void updateGroupPolicyOnce(
        const std::string& groupId,
        const core::ContainerPolicy& policies,
        std::optional<PendingCarry>& carry
    );

    // A commit released to the bridge with no known outcome. A retry of the same operation resends exactly this
    // (no second statement, no wasted epoch); any other operation drops it after one resend and plans afresh (a fork
    // that leaves open is one a bridge can reach by withholding anyway).
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
    // client, or an earlier call of an event op past its window, was completed first; read again. Deferred: a self-update yields to another op's commit.
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
    // whether a different op may resend it (every app op; not the deferred self-update).
    Settled settle(const std::string& groupId, const std::string& op, bool mayCompleteOther);
    // Sends a signed statement and keeps `commit` until its outcome is known. Throws StalePlan for a plan
    // behind the pin. A refusal as a lost race (`isRetryableCommitRejection`) is remembered for `chainTo`.
    void submit(const std::string& groupId, const keytree::CommitStatement& statement, UnresolvedCommit commit);
    void forgetUnresolved(const std::string& groupId, const std::string& digest);
    // The commit's outcome is known and it landed: forgotten and `landed`.
    void complete(const std::string& groupId, const UnresolvedCommit& commit);
    // A read to plan a commit for `op` on: verified, with this client's unresolved commit to the group settled first.
    // nullopt: `op` itself landed (Settled::Done). An unverified read is returned to be refused by the plan.
    std::optional<server::GroupInfo> readForCommit(
        const server::GroupGetModel& model,
        keytree::TreeVerifier::Scope scope,
        const std::string& op,
        bool mayCompleteOther = true
    );

    // `group` must have passed `verifyTree` at plan scope. `tolerateBrokenClimb`: a climb that fails on the served
    // edges (not on membership) is logged and the state returned anyway — a removal plans from public state alone.
    keytree::TreeGroupState climbForPlanning(
        const server::GroupInfo& group,
        const std::shared_ptr<keytree::TreeKeyCache>& cache,
        bool tolerateBrokenClimb = false
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

    // The `UnresolvedCommit::landed` of a commit that opened `statement.keyVersion`: pins it before anything reads the
    // group again (the state it replaced is refused from then on) and keeps the new grant key, the epoch's published
    // one. `roster` is the one the statement signed. Captures copies, nothing by reference.
    std::function<void()> landedEpoch(
        const std::string& contextId,
        const keytree::CommitStatement& statement,
        const RosterAfterChange& roster,
        const keytree::GroupRules& rules,
        const privmx::crypto::PrivateKey& grantKey
    );

    static void commitWithRetry(const std::function<void()>& attempt);
    static bool isRetryableCommitRejection(const privmx::utils::PrivmxException& e);

    // Refills the blank nodes of the caller's own keyed path. A failure leaves the tree as it was; one lost to a
    // concurrent commit (`isRetryableCommitRejection`) is rescheduled, up to MAX_SELF_UPDATE_ATTEMPTS in all.
    void selfUpdate(const std::string& groupId);
    // Records one when `group` (a seated, verified read) shows the caller's path needs it, due not before a random
    // point within a window that grows with the group for the seat that heals first, one window later for any other
    // (`healsFirst`), so a group's members do not all commit at once. At most one recorded per group.
    void scheduleSelfUpdateIfNeeded(const std::string& groupId, const server::GroupInfo& group);
    void scheduleSelfUpdate(const std::string& groupId, std::int64_t windowMs, bool healsFirst, int attempts = 0);
    // The flush point, at the end of a public call on `groupId` that succeeded: runs the group's due ladder checks
    // and self-update. Best-effort: failures are logged, never thrown. Key
    // resolution for containers only records work; nothing commits there.
    void runDueWork(const std::string& groupId);

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

    // `clamp(numLeaves·8 ms, 1 s, 120 s)`: how far a group's members spread their deferred work.
    static std::int64_t backgroundWindowMs(const server::GroupInfo& group);

    // Includes open file handles, not just the key caches.
    void dropEnvelopeState();

    // Every key memoized for the group (tree key cache, epoch keys, envelope keys and grant epochs): a deleted id may
    // come back as another group, whose epochs share the numbers but not the keys.
    void forgetGroupKeys(const std::string& groupId);

    // Length-prefixed `groupId`, so one pair cannot collide with another under a different split.
    static std::string memoKeyFor(const std::string& groupId, const std::string& suffix);

    // Reaches back through the whole archive, however old the key is. A key past the cached head comes from
    // `groupGetEpochKeys` by its id, not from a re-read of the group (`groupGet` serves only the current epochs).
    core::DecryptedEncKeyV2 encKeyById(const std::string& groupId, const std::string& keyId);

    // The sender only ever held a public key, so its epoch is recovered from the group's published history
    // (`groupGetEpochKeys` by that key) rather than carried on the wire.
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

    // Lock order: commitLock(groupId) -> _dueMutex. _dueMutex, _unresolvedMutex and
    // _pendingCarryMutex are leaves; `runDueWork` holds none of them while running a task.
    //
    // No thread of its own: deferred work (self-updates) is recorded and runs at the end
    // of the next public call on the group, after `due` (a "not before"). Records are dropped on disconnect.
    std::mutex _dueMutex;
    struct PendingSelfUpdate {
        std::chrono::steady_clock::time_point due;
        std::int64_t windowMs; // the delay window it was scheduled with, reused by a retry
        int attempts;          // lost races so far, counted toward MAX_SELF_UPDATE_ATTEMPTS
    };
    std::map<std::string, PendingSelfUpdate> _selfUpdatePending;
    static constexpr int MAX_SELF_UPDATE_ATTEMPTS = 3;
    bool _dueWorkOff = false; // tests: `runDueWork` does nothing

    // One released statement per prevDigest. The bodies survive reconnects on purpose: a dropped
    // connection is the commonest unknown outcome, and the same call retried after it must resend, not be held back.
    std::mutex _unresolvedMutex;                                     // guards both maps
    std::map<std::string, std::shared_ptr<std::mutex>> _commitLocks; // never pruned: one per group committed to
    std::map<std::string, UnresolvedCommit> _unresolved;
    // Limit: in memory only. A crash before the retry leaves the planes refused until a member holding `update`
    // writes metadata (documented on updateGroupPolicy).
    std::mutex _pendingCarryMutex;
    std::map<std::string, PendingCarry> _pendingCarry;
    friend struct GroupApiImplTestAccess; // tests reach selfUpdate() and turn `runDueWork` off
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_
