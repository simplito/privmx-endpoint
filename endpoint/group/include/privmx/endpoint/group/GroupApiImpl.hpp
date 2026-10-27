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
        const std::optional<core::ContainerPolicy>& policies
    );

    void addGroupMembers(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers);

    void removeGroupMembers(const std::string& groupId, const std::vector<std::string>& userIds);

    void rotateGroupKey(const std::string& groupId);
    bool renewLeaf(const std::string& groupId, const std::string& previousUserPrivKey);

    // The pins the PinStore holds for `previous` (an earlier identity key of this user), taken only for groups
    // with no pin under the current key (never replacing or raising one) and saved under the current key. No store,
    // the current key, or adopted already: nothing. Throws core::LocalStateIntegrityException when the previous
    // key's stored pins do not open (nothing adopted), and what the store throws.
    void adoptPreviousIdentity(const privmx::crypto::PrivateKey& previous);

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
    core::DecryptedEncKeyV2 encKeyById(const std::string& groupId, const std::string& keyId);

    ServerApi _serverApi;
    SubscriberImpl _subscriber;

    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    std::shared_ptr<GroupDataSchemaMapper> _groupDataSchemaMapper;
    keytree::TreeVerifier _treeVerifier;
    GroupEnvelopeEncryptor _envelopeEncryptor;
    // Open file handles, dropped with the sessions' keys on connect and disconnect.
    GroupEnvelopeFiles _envelopeFiles{_envelopeEncryptor, _connection};
    // Every group's keys, commit state and pending work.
    GroupSessions _sessions;
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
