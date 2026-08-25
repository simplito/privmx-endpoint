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
    core::PagingList<GroupSummary> listGroups(const std::string& contextId, const core::PagingQuery& pagingQuery);


    std::unordered_map<std::string, core::GroupEpochInfo> fetchGroupEpochs(
        const std::string& contextId,
        const std::vector<std::string>& groupIds
    );

    static core::ModuleBaseApi::GroupResolvers makeGroupResolvers(const std::shared_ptr<GroupApiImpl>& groupApiImpl);

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
    server::GroupGetKeyArchiveResult fetchKeyArchive(
        const std::string& groupId,
        int64_t targetEpoch,
        int64_t currentEpoch
    );

private:
    // Verify winner's rotation payload, decrypt+register their epoch key, invalidate cache
    void adoptRotatedAlready(const std::string& groupId, const server::RotatedAlreadyPayload& payload);
    void processNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    void processConnectedEvent();
    void processDisconnectedEvent();
    virtual std::pair<core::ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string moduleId) override;
    core::ModuleKeys groupToModuleKeys(const server::GroupInfo& group);

    /** Roster entries as tree leaves, in a stable order — the seating is part of the state the bridge checks. */
    static std::vector<keytree::TreeMember> toTreeMembers(
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers
    );

    /**
     * The roster as unparsed base58 keys, indexed by user id.
     *
     * What `toTreeMembers` does, minus the parsing: building a group wraps to every member so it needs every key,
     * but a membership change wraps to the `log n` leaves beside one path. At four thousand members parsing the
     * rest costs ~0.75 s of subgroup checks for nothing.
     */
    static std::map<std::string, std::string> rosterKeyStrings(
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers
    );

    /**
     * Climbs the tree so the caller holds the node keys a plan needs, and returns the current runtime state.
     *
     * Both membership changes need this first: an addition needs the seat's parent key, a removal needs every key
     * on the departing leaf's path plus the current grant key to wrap the first ladder rung.
     *
     * @param cache the group's own cache — passed in rather than looked up, so that the climb and the plan that
     *              follows it are guaranteed to use the same one even if the group is invalidated in between.
     *              Shared ownership, not a reference: it keeps the cache alive for the whole operation even if
     *              another thread drops the group from the registry mid-climb.
     */
    keytree::TreeGroupState climbForPlanning(
        const server::GroupInfo& group,
        const std::shared_ptr<keytree::TreeKeyCache>& cache
    );

    /**
     * Builds the complete rung set a rotation owes, fetching the archive and recovering the older grant keys first.
     *
     * The recovery is the point. A rung may only be published at the moment its own epoch is created, so whatever
     * this set omits is omitted for good — and a manager rotating from a freshly started client holds exactly one
     * grant key, the current one. Left to the cache, such a rotation would publish the unit rung alone; enough of
     * those in a row and the ladder is linear, which puts history further back than a reader's walk bound out of
     * reach for everyone. So the keys are gathered from the archive (about `log2(epoch)` unwraps) before any rung
     * is wrapped, and a key that cannot be recovered aborts the rotation instead of shortening the set.
     *
     * @param cache the group's own cache, already holding `sk_{newEpoch-1}` from the climb
     * @throws IncompleteEpochLadderException when some rung the epoch owes cannot be built
     */
    std::vector<keytree::ArchiveRung> buildRotationRungs(
        const server::GroupInfo& group,
        std::uint32_t newEpoch,
        const privmx::crypto::PublicKey& newGrantPublicKey,
        const std::optional<privmx::crypto::PrivateKey>& previousEpochKey,
        const std::string& author,
        keytree::TreeKeyCache& cache
    );

    /**
     * Drops a group's node keys once the server reports an epoch newer than any grant key held for it.
     *
     * A removal refreshes the generations along the departing leaf's path; those node keys are dead, while the
     * grant keys stay valid and are still needed to publish ladder rungs later. Called from every path that
     * learns a group's current epoch, so a client that missed the event still converges on its next read.
     */
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
    /**
     * Per-group caches of tree node keys and epoch grant keys, shared by the climb and the descent: the climb
     * supplies the current epoch, the descent walks back from it. Purely an optimisation — losing one costs
     * bandwidth, not access, because everything is rebuildable from what the bridge stores.
     *
     * One cache per group, never one for all of them: nothing inside a cache is keyed by group, and epochs start
     * at 1 everywhere, so a shared cache aliases two groups on their first entries.
     */
    keytree::TreeKeyCacheRegistry _treeKeyCaches;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_
