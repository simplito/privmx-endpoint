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
#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaMapper.hpp"
#include "privmx/endpoint/group/keytree/GroupKeyResolver.hpp"
#include "privmx/endpoint/group/keytree/TreeKeyCache.hpp"
#include "privmx/endpoint/group/keytree/TreeKeyCacheRegistry.hpp"
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

    // Grant key distributed by a hidden key tree, not one wrap per member: removal costs the wraps on one path,
    // addition a single wrap at the same epoch. The grant private key stays out of the metadata on purpose.
    std::string createGroup(
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies
    );

    // Seats one member at the same epoch; `users`/`managers` are the full roster after the addition. Any member
    // can climb to the seat's parent, so this is not manager-only cryptographically — the bridge still gates it.
    void addGroupMember(
        const std::string& groupId,
        const core::UserWithPubKey& newMember,
        bool asManager,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta
    );

    // Removes one member and advances the epoch; `users`/`managers` are the roster that remains. Blanks the leaf,
    // refreshes its direct path, rotates the grant keypair and publishes the ladder rungs — none is safe alone.
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
    core::PagingList<GroupSummary> listGroups(const std::string& contextId, const core::PagingQuery& pagingQuery);

    std::unordered_map<std::string, core::GroupEpochInfo> fetchGroupEpochs(
        const std::string& contextId,
        const std::vector<std::string>& groupIds
    );

    static core::ModuleBaseApi::GroupResolvers makeGroupResolvers(const std::shared_ptr<GroupApiImpl>& groupApiImpl);

    // Feeds straight into `ModuleBaseApi::initGroupResolvers` so a module never has to branch on whether it was
    // given a GroupApi. Returns nullopt when it wasn't.
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
    // The grant private key for an epoch (`0` means current): climbs from the caller's leaf to the current grant
    // key, then descends the Epoch Ladder for an older one. Throws EncryptionKeyValidationException if it can't.
    privmx::crypto::PrivateKey resolveGroupPrivKey(const std::string& groupId, int64_t epoch = 0);

    // Renders a resolver failure so policy (era boundary, pruning) reads differently from an attack.
    static std::string describeResolveFailure(const keytree::ResolveResult& resolved);

    // Fetches the Epoch Ladder for one descent, windowed to the epochs it passes through, so the request is
    // proportional to the hop rather than to how long the group has existed.
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

    void withHistoryFrom(server::GroupGetModel& params, const std::string& groupId);
    static std::vector<keytree::TreeMember> toTreeMembers(
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers
    );

    // The roster as unparsed base58 keys, indexed by user id — `toTreeMembers` minus the parsing, since a
    // membership change only wraps to the `log n` leaves beside one path and parsing the rest is wasted.
    static std::map<std::string, std::string> rosterKeyStrings(
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers
    );

    // Climbs for the node keys a plan needs (the seat's parent for an addition, the whole leaf path plus the grant
    // key for a removal). `cache` is passed in and shared-owned so climb and plan use the same one, alive till done.
    keytree::TreeGroupState climbForPlanning(
        const server::GroupInfo& group,
        const std::shared_ptr<keytree::TreeKeyCache>& cache
    );

    // Builds the complete rung set a rotation owes, recovering the older grant keys from the archive first: a rung
    // is publishable only at its own epoch, so a short set is permanent and enough of them make the ladder linear.
    std::vector<keytree::ArchiveRung> buildRotationRungs(
        const server::GroupInfo& group,
        std::uint32_t newEpoch,
        const privmx::crypto::PublicKey& newGrantPublicKey,
        const std::optional<privmx::crypto::PrivateKey>& previousEpochKey,
        const std::string& author,
        keytree::TreeKeyCache& cache
    );

    // Drops a group's node keys once the server reports a newer epoch — the removal refreshed that path, while the
    // grant keys stay valid for rungs. Called from every path that learns an epoch, so a missed event converges.
    void noteGroupEpoch(const std::string& groupId, std::uint32_t epoch);

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
    // Per-group caches of node keys and epoch grant keys, shared by climb and descent; purely an optimisation.
    // One per group, never one for all: nothing inside is keyed by group and epochs start at 1 everywhere.
    keytree::TreeKeyCacheRegistry _treeKeyCaches;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_
