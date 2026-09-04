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

    void addGroupMembers(const GroupId& groupId, const std::vector<GroupMemberToAdd>& newMembers);

    void removeGroupMembers(const GroupId& groupId, const std::vector<std::string>& userIds);

    void updateGroup(
        const GroupId& groupId,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const int64_t version,
        const bool force,
        const bool forceGenerateNewKey,
        const std::optional<core::ContainerPolicy>& policies,
        bool allowRotationRetry = true
    );
    void deleteGroup(const GroupId& groupId);

    Group getGroup(const GroupId& groupId);
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
    privmx::crypto::PrivateKey resolveGroupPrivKey(const GroupId& groupId, int64_t epoch = 0);

    Envelope encrypt(const GroupId& groupId, const core::Buffer& content);
    DecryptedEnvelope decrypt(const Envelope& envelope);
    Envelope encryptAnonymously(
        const GroupId& groupId,
        const PubKey& groupPubKey,
        const core::Buffer& content
    );

    FileHandle beginFileEncryption(const GroupId& groupId, FileSize size);
    FileHandle beginFileEncryptionAnonymously(
        const GroupId& groupId,
        const PubKey& groupPubKey,
        FileSize size
    );
    core::Buffer encryptFileChunk(FileHandle fileHandle, const core::Buffer& plainChunk);
    FileHandle beginFileDecryption(const Envelope& envelope);
    core::Buffer decryptFileChunk(FileHandle fileHandle, const core::Buffer& cipherChunk);
    CipherOffset seekInEncryptedFile(FileHandle fileHandle, FilePosition position);
    Envelope finishFileEncryption(FileHandle fileHandle);
    DecryptedFileInfo finishFileDecryption(FileHandle fileHandle);

    /**
     * The routes to one key, out of every route the group publishes.
     *
     * Handing the whole archive to the key provider makes it resolve a grant key — and the server answer for
     * one — per key the group has ever held, on every envelope opened. Narrowing it first is what keeps that
     * cost at one.
     */
    static std::vector<core::server::GroupKeysEntry> onlyKeyId(
        const std::vector<core::server::GroupKeysEntry>& all,
        const KeyId& keyId
    );

    static std::string describeResolveFailure(const keytree::ResolveResult& resolved);

    server::GroupGetKeyArchiveResult fetchKeyArchive(
        const GroupId& groupId,
        int64_t targetEpoch,
        int64_t currentEpoch
    );

private:
    void adoptRotatedAlready(const GroupId& groupId, const server::RotatedAlreadyPayload& payload);
    void processNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    void processConnectedEvent();
    void processDisconnectedEvent();
    virtual std::pair<core::ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string moduleId) override;
    core::ModuleKeys groupToModuleKeys(const server::GroupInfo& group);

    static std::vector<keytree::TreeMember> toTreeMembers(
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers
    );

    /** A roster split the way `prepareContainerUpdate` wants it. */
    struct RosterAfterChange {
        std::vector<core::UserWithPubKey> users;
        std::vector<core::UserWithPubKey> managers;
    };
    static RosterAfterChange rosterOf(const Group& verified);
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

    void dropNodeKeysIfEpochAdvanced(const GroupId& groupId, std::uint32_t epoch);

    /** The group's symmetric data key named by `keyId`, however far back in the archive it lives. */
    core::DecryptedEncKeyV2 encKeyById(const GroupId& groupId, const KeyId& keyId);


    /**
     * The grant private key matching a public key an envelope names.
     *
     * The sender only ever held a public key, so the epoch it belongs to is recovered from the group's own
     * published history rather than carried on the wire.
     */
    privmx::crypto::PrivateKey grantKeyForPubKey(
        const GroupId& groupId,
        const PubKey& groupPubKeyBase58
    );

    /**
     * One in-flight encrypt or decrypt of a file.
     *
     * Individual handles are not locked — only the map is, which matches how Store treats its file handles.
     * Driving one handle from two threads corrupts its buffer.
     */
    struct EnvelopeFileState {
        bool reading;
        EnvelopeType type;
        std::string groupId;
        std::string keyId;        //< member files only
        std::string groupKey;     //< member files only
        std::string groupPubKey;  //< anonymous seals only, base58-DER
        std::string authorPubKey; //< opening only: provenance handed back at finish
        std::string fileKey;
        ChunkIndex index = 0;       //< next chunk to seal or open
        ByteCount plainSize = 0;    //< declared plaintext length of the whole file
        ByteCount written = 0;      //< write side: plaintext accepted so far
        ByteCount skipInChunk = 0;  //< read side: bytes to drop off the next chunk after a seek
        bool seeked = false;          //< read side: completeness is no longer checkable
        std::string buffer;         //< bytes not yet forming a whole chunk
    };
    std::shared_ptr<EnvelopeFileState> getFileState(FileHandle fileHandle, bool wantReading);
    void releaseFileHandle(FileHandle fileHandle);
    core::Buffer drainChunks(const std::shared_ptr<EnvelopeFileState>& state);
    /** Shared tail of both finishers: completeness check, then release whatever the outcome. */
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
    /**
     * Keys already unwrapped for envelopes, by `groupId + "\n" + keyId`.
     *
     * Sound because a keyId names one immutable piece of key material: unwrapping it twice can only ever give
     * the same answer. Dropped alongside every other key cache on connect and disconnect, so a key cannot
     * outlive the session that opened it — an era cut therefore takes effect at reconnect, exactly as it
     * already does for the grant keys `TreeKeyCache` deliberately keeps.
     */
    privmx::utils::ThreadSaveMap<std::string, core::DecryptedEncKeyV2> _envelopeKeys;
    privmx::utils::ThreadSaveMap<int64_t, std::shared_ptr<EnvelopeFileState>> _envelopeFiles;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_
