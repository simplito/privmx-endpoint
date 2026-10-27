/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIHOOKS_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIHOOKS_HPP_

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>

#include "privmx/endpoint/group/GroupSession.hpp"
#include "privmx/endpoint/group/GroupTypes.hpp"
#include "privmx/endpoint/group/ServerApi.hpp"
#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/VerifiedGroup.hpp"
#include "privmx/endpoint/group/keytree/TreeVerifier.hpp"

namespace privmx {
namespace endpoint {
namespace group {

// What the group units (keys, commit engine, operations, metadata) take from the GroupApiImpl they live in: its
// checked reads and pin saves, and its container base (key preparation, the UserVerifier, the module key cache).
// Bound once, in its constructor, to that instance; every unit holding it lives inside the same instance.
struct GroupApiHooks {
    // `readGroup`, saving the pins its check moved.
    std::function<GroupRead(const server::GroupGetModel& model, keytree::TreeVerifier::Scope scope)> read;
    // A path read every key is chosen or cached from (`GroupApiImpl::readGroupForKeys`).
    std::function<VerifiedGroup(const std::string& groupId)> readForKeys;
    // The pins into the store now (an own commit, before the call returns).
    std::function<void()> savePins;
    // A container create with empty rosters: the group wraps its metadata key to its own grant key.
    std::function<core::ContainerCreateContext(const std::string& contextId)> prepareCreate;
    // A container update off the group's head entry, with no per-member key entries.
    std::function<core::ContainerUpdateContext(
        const server::GroupInfo& group,
        const std::string& resourceId,
        const RosterAfterChange& roster,
        bool newKey
    )>
        prepareUpdate;
    std::function<std::vector<core::server::GroupKeyEntrySet>(
        const std::vector<core::GroupGrantWithKey>& groups,
        const core::EncKey& key,
        const core::DataIntegrityObject& dio,
        const std::string& contextId,
        const std::string& resourceId,
        const std::string& containerSecret
    )>
        buildGroupKeyEntries;
    // The application's UserVerifier vouches for every (userId, pubKey) pair. Throws UserVerificationFailureException.
    std::function<void(const std::string& contextId, const std::vector<core::UserWithPubKey>& users)>
        assertUserKeysVerified;
    // Public keys for exactly these members, from the Context user list, vouched for as above.
    std::function<std::map<std::string, std::string>(const std::string& contextId, const std::vector<std::string>& userIds)>
        resolveMemberKeys;
    std::function<void(const std::string& groupId)> invalidateModuleKeys;
};

// What every group unit of one GroupApiImpl shares: references into it, for its lifetime.
struct GroupDeps {
    ServerApi& serverApi;
    keytree::TreeVerifier& treeVerifier;
    const core::Connection& connection;
    GroupSessions& sessions;
    const privmx::crypto::PrivateKey& userPrivKey;
    const GroupApiHooks& facade;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIHOOKS_HPP_
