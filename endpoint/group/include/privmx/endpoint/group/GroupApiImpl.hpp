#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_

#include <atomic>
#include <memory>
#include <optional>
#include <string>

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
#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaMapper.hpp"
#include "privmx/endpoint/group/keytree/GroupKeyResolver.hpp"
#include <privmx/utils/ManualManagedClass.hpp>

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

    /**
     * Creates a group whose grant key is distributed by a hidden key tree instead of one wrap per member.
     *
     * The difference this makes shows up later, not here: removing a member costs the wraps on one path rather
     * than one per remaining member, and adding one costs a single wrap and does not advance the epoch, so no
     * container the group can read goes stale. Creation itself costs the same order either way.
     *
     * The grant private key is deliberately **not** placed in the group's encrypted metadata. Putting it there
     * would hand it to every member through the metadata key, and the metadata key would then have to be
     * re-wrapped for everyone on each removal — which is exactly the cost the tree exists to remove.
     */
    std::string createGroupWithKeyTree(
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies
    );

    /**
     * Seats one member in a tree-backed group, at the same epoch.
     *
     * @param users    the full roster after the addition, the newcomer included
     * @param managers likewise
     *
     * The caller must be able to climb to the seat's parent, which any member can; this is not a manager-only
     * operation cryptographically, though the bridge still applies its usual policy gate.
     */
    void addGroupMember(
        const std::string& groupId,
        const core::UserWithPubKey& newMember,
        bool asManager,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta
    );

    /**
     * Removes one member from a tree-backed group and advances the epoch.
     *
     * @param users    the roster that remains, the departing member excluded
     * @param managers likewise
     *
     * Does four things at once because none of them is safe alone: blanks the leaf, refreshes its direct path
     * with fresh random keys, rotates the grant keypair, and publishes the ladder rungs that keep the older
     * epochs reachable from the new one.
     */
    void removeGroupMember(
        const std::string& groupId,
        const std::string& userId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta
    );

    void updateGroup(
        const std::string& groupId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const int64_t version,
        const bool force,
        const bool forceGenerateNewKey,
        const std::optional<core::ContainerPolicy>& policies,
        bool allowRotationRetry = true
    );
    void deleteGroup(const std::string& groupId);

    Group getGroup(const std::string& groupId);
    core::PagingList<Group> listGroups(const std::string& contextId, const core::PagingQuery& pagingQuery);

    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);
    std::string buildSubscriptionQuery(
        EventType eventType,
        EventSelectorType selectorType,
        const std::string& selectorId
    );
    /**
     * The group's grant private key for an epoch (`0` means current).
     *
     * Climbs the hidden key tree from the caller's leaf to the current epoch's grant key, then descends the
     * Epoch Ladder if an older epoch was requested.
     *
     * @throws core::EncryptionKeyValidationException when the key tree cannot be resolved
     */
    privmx::crypto::PrivateKey resolveGroupPrivKey(const std::string& groupId, int64_t epoch = 0);

    /** Renders a resolver failure so policy (era boundary, pruning) reads differently from an attack. */
    static std::string describeResolveFailure(const keytree::ResolveResult& resolved);

    /**
     * Fetches the Epoch Ladder for one descent, windowed to the epochs it passes through.
     *
     * Only a descent needs it, so only a descent pays for it: the request is proportional to the hop rather
     * than to how long the group has existed.
     */
    server::GroupGetKeyArchiveResult fetchKeyArchive(const std::string& groupId, int64_t targetEpoch, int64_t currentEpoch);

private:
    // EP-11: verify winner's rotation payload, decrypt+register their epoch key, invalidate cache
    void adoptRotatedAlready(const std::string& groupId, const server::RotatedAlreadyPayload& payload);
    void processNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    void processConnectedEvent();
    void processDisconnectedEvent();
    virtual std::pair<core::ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string moduleId) override;
    core::ModuleKeys groupToModuleKeys(const server::GroupInfo& group);

    /**
     * Registers the group's own grant key, so the metadata key it wrapped to itself can be opened.
     *
     * A tree-backed group holds one metadata key ciphertext per epoch instead of one per member, which is what
     * keeps a removal O(1) in the roster; the cost is that reading the group requires climbing first.
     */
    void registerOwnGrantKeys(const server::GroupInfo& group);

    /** Roster entries as tree leaves, in a stable order — the seating is part of the state the bridge checks. */
    static std::vector<keytree::TreeMember> toTreeMembers(
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers
    );

    /**
     * Climbs the tree so the caller holds the node keys a plan needs, and returns the current runtime state.
     *
     * Both membership changes need this first: an addition needs the seat's parent key, a removal needs every key
     * on the departing leaf's path plus the current grant key to wrap the first ladder rung.
     */
    keytree::TreeGroupState climbForPlanning(const server::GroupInfo& group);

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
    /**
     * Cache of tree node keys and per-epoch grant keys, shared by the climb and the descent: the climb supplies
     * the current epoch, the descent walks back from it. Purely an optimisation — losing it costs bandwidth, not
     * access, because everything is rebuildable from what the bridge stores.
     */
    keytree::TreeKeyStore _treeKeyStore;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_
