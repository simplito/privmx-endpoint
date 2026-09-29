#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>

#include "privmx/endpoint/core/ContainerKeyCache.hpp"
#include "privmx/endpoint/core/Factory.hpp"
#include "privmx/endpoint/core/ModuleBaseApi.hpp"
#include "privmx/endpoint/group/Constants.hpp"
#include "privmx/endpoint/group/Events.hpp"
#include "privmx/endpoint/group/GroupApi.hpp"
#include "privmx/endpoint/group/ServerApi.hpp"
#include "privmx/endpoint/group/SubscriberImpl.hpp"
#include "privmx/endpoint/group/encryptors/envelope/GroupEnvelopeEncryptor.hpp"
#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaMapper.hpp"
#include "privmx/endpoint/group/keytree/GroupKeyResolver.hpp"
#include "privmx/endpoint/group/keytree/TreeKeyCache.hpp"
#include "privmx/endpoint/group/keytree/TreeKeyCacheRegistry.hpp"
#include <privmx/utils/ManualManagedClass.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>

namespace privmx {
namespace endpoint {
namespace group {

class GroupApiImpl : public privmx::utils::ManualManagedClass<GroupApiImpl>, protected core::ModuleBaseApi {
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

    // Called after a removal commits, never as part of it: an entry left at epoch N is still openable and
    // re-taggable by the removed member, and best-effort here keeps the removal's own write single-plane.
    void refreshMetadataEpochAfterRemoval(const std::string& groupId);

    void updateGroupPublicMeta(
        const std::string& groupId,
        const core::Buffer& publicMeta,
        const int64_t version,
        bool allowRotationRetry = true
    );
    void updateGroupPrivateMeta(
        const std::string& groupId,
        const core::Buffer& privateMeta,
        const int64_t version,
        bool allowRotationRetry = true
    );
    void updateGroupPolicy(const std::string& groupId, const core::ContainerPolicy& policies);
    void deleteGroup(const std::string& groupId);

    Group getGroup(const std::string& groupId);
    core::PagingList<GroupSummary> listGroups(const std::string& contextId, const core::PagingQuery& pagingQuery);

    std::unordered_map<std::string, core::GroupEpochInfo> fetchGroupEpochs(
        const std::string& contextId,
        const std::vector<std::string>& groupIds
    );

    static core::ModuleBaseApi::GroupResolvers makeGroupResolvers(const std::shared_ptr<GroupApiImpl>& groupApiImpl);
    static std::optional<core::ModuleBaseApi::GroupResolvers> makeGroupResolvers(
        const std::optional<GroupApi>& groupApi
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
    privmx::crypto::PrivateKey resolveGroupPrivKey(const std::string& groupId, int64_t epoch = 0);

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
    // rather than one per key the group has ever held.
    static std::vector<core::server::GroupKeysEntry> filterToKeyId(
        const std::vector<core::server::GroupKeysEntry>& all,
        const std::string& keyId
    );

    static std::string describeResolveFailure(const keytree::ResolveResult& resolved);

    server::GroupGetKeyArchiveResult fetchKeyArchive(
        const std::string& groupId,
        int64_t targetEpoch,
        int64_t currentEpoch
    );

private:
    void adoptRotatedAlready(const std::string& groupId, const server::RotatedAlreadyPayload& payload);
    void processNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    void processConnectedEvent();
    void processDisconnectedEvent();
    virtual std::pair<core::ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string moduleId) override;
    core::ModuleKeys groupToModuleKeys(const server::GroupInfo& group);

    static std::vector<keytree::TreeMember> toTreeMembers(
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers
    );

    // A roster split the way `prepareContainerUpdate` wants it.
    struct RosterAfterChange {
        std::vector<core::UserWithPubKey> users;
        std::vector<core::UserWithPubKey> managers;
    };
    static RosterAfterChange rosterFromUserIds(
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers
    );

    // The head, the resource id, the epoch, and a key proven to be the current epoch's.
    struct MetaWriteContext {
        std::string resourceId;
        int64_t currentEpoch;
        core::ContainerUpdateContext ctx;
    };
    // The entire shared prologue of both metadata writes; neither plane reads the other's envelope.
    // Kept in one place so the epoch guard cannot drift between the two callers.
    MetaWriteContext prepareMetaWrite(const std::string& groupId);

    std::map<std::string, std::string> resolveMemberKeys(
        const std::string& contextId,
        const std::vector<std::string>& userIds
    );

    keytree::TreeGroupState climbForPlanning(
        const server::GroupInfo& group,
        const std::shared_ptr<keytree::TreeKeyCache>& cache
    );

    std::vector<keytree::ArchiveRung> buildRotationRungs(
        const server::GroupInfo& group,
        std::uint32_t newEpoch,
        const privmx::crypto::PublicKey& newGrantPublicKey,
        const std::optional<privmx::crypto::PrivateKey>& previousEpochKey,
        const std::string& author,
        keytree::TreeKeyCache& cache
    );

    void dropNodeKeysIfEpochAdvanced(const std::string& groupId, std::uint32_t epoch);

    // Includes open file handles, not just the key caches.
    void dropEnvelopeState();

    // Length-prefixed `groupId`, so one pair cannot collide with another under a different split.
    static std::string memoKeyFor(const std::string& groupId, const std::string& suffix);

    // Reaches back through the whole archive, however old the key is.
    core::DecryptedEncKeyV2 encKeyById(const std::string& groupId, const std::string& keyId);

    // The sender only ever held a public key, so its epoch is recovered from the group's published history
    // rather than carried on the wire.
    privmx::crypto::PrivateKey grantKeyForPubKey(const std::string& groupId, const std::string& groupPubKeyBase58);

    // Individual handles are not locked — only the map is, as in Store. Driving one handle from two threads
    // corrupts its buffer.
    struct EnvelopeFileState {
        bool reading;
        EnvelopeType type;
        std::string groupId;
        std::string keyId;        // member files only
        std::string groupKey;     // member files only
        std::string groupPubKey;  // anonymous seals only, base58-DER
        std::string authorPubKey; // opening only: provenance handed back at finish
        std::string fileKey;
        ChunkIndex index = 0;      // next chunk to seal or open
        ByteCount plainSize = 0;   // declared plaintext length of the whole file
        ByteCount written = 0;     // write side: plaintext accepted so far
        ByteCount skipInChunk = 0; // read side: bytes to drop off the next chunk after a seek
        bool seeked = false;       // read side: completeness is no longer checkable
        std::string buffer;        // bytes not yet forming a whole chunk
    };
    std::shared_ptr<EnvelopeFileState> getFileState(FileHandle fileHandle, bool wantReading);
    void releaseFileHandle(FileHandle fileHandle);
    core::Buffer drainChunks(const std::shared_ptr<EnvelopeFileState>& state);
    // Shared tail of both finishers: completeness check, then release whatever the outcome.
    std::shared_ptr<EnvelopeFileState> finishFile(FileHandle fileHandle, bool wantReading);

    privfs::RpcGateway::Ptr _gateway;
    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::string _host;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    core::Connection _connection;
    ServerApi _serverApi;
    SubscriberImpl _subscriber;

    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    std::shared_ptr<GroupDataSchemaMapper> _groupDataSchemaMapper;
    keytree::TreeKeyCacheRegistry _treeKeyCaches;
    GroupEnvelopeEncryptor _envelopeEncryptor;
    // Keys already unwrapped for envelopes, by `memoKeyFor(groupId, keyId)`; a keyId names one immutable piece
    // of key material. Dropped on connect and disconnect, so an era cut takes effect at reconnect.
    privmx::utils::ThreadSaveMap<std::string, core::DecryptedEncKeyV2> _envelopeKeys;
    // Which epoch a published grant public key belongs to, by `memoKeyFor(groupId, pubKeyBase58)`.
    privmx::utils::ThreadSaveMap<std::string, int64_t> _envelopeGrantEpochs;
    privmx::utils::ThreadSaveMap<int64_t, std::shared_ptr<EnvelopeFileState>> _envelopeFiles;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_
