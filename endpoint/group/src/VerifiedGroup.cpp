/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/VerifiedGroup.hpp"

#include <privmx/endpoint/core/ConnectionImpl.hpp>

#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/keytree/GroupKeyResolver.hpp"

using namespace privmx::endpoint;
using namespace group;

server::GroupGetModel group::pathRead(const std::string& groupId) {
    return server::GroupGetModel{
        .groupId = groupId, .type = {}, .scope = {}, .forUserIds = {}, .forNewMembers = {}, .fromRosterVersion = {}
    };
}

server::GroupGetModel group::planRead(
    const std::string& groupId,
    std::optional<std::vector<std::string>> forUserIds,
    std::optional<std::int64_t> forNewMembers
) {
    return server::GroupGetModel{
        .groupId = groupId,
        .type = {},
        .scope = std::string("plan"),
        .forUserIds = forUserIds,
        .forNewMembers = forNewMembers,
        .fromRosterVersion = {}
    };
}

keytree::TreeVerifier::Environment group::treeEnvironment(
    ServerApi& serverApi,
    const core::Connection& connection,
    const std::string& groupId
) {
    keytree::TreeVerifier::Environment environment;
    environment.verifyUsers = [&connection](const std::vector<core::VerificationRequest>& requests) {
        return connection.getImpl()->getUserVerifier()->verify(requests);
    };
    // One page: the bridge answers at most 256 statements a call, and the verifier asks again from where it stopped.
    environment.commitsBetween = [&serverApi, groupId](std::uint64_t fromSeq, std::uint64_t toSeq) {
        return serverApi.groupGetTreeCommits(
            server::GroupGetTreeCommitsModel{
                .groupId = groupId, .fromSeq = static_cast<std::int64_t>(fromSeq), .toSeq = static_cast<std::int64_t>(toSeq)
            }
        );
    };
    return environment;
}

GroupRead group::readGroup(
    ServerApi& serverApi,
    keytree::TreeVerifier& treeVerifier,
    const core::Connection& connection,
    const server::GroupGetModel& model,
    keytree::TreeVerifier::Scope scope,
    const std::function<void()>& afterVerify
) {
    server::GroupInfo group = serverApi.groupGet(model).group;
    // Whatever this verification moved, refusals included.
    struct AfterVerify {
        const std::function<void()>& run;
        ~AfterVerify() { run(); }
    } after{afterVerify};
    if (!keytree::GroupKeyResolver::hasTree(group) ||
        !keytree::GroupKeyResolver::hasSupportedTree(group) ||
        !keytree::GroupKeyResolver::ownUserId(group).has_value()) {
        return GroupRead{.verified = std::nullopt, .unseated = std::move(group)};
    }
    // The hash binds the seat to a user id, not to this caller: every climb starts there and every commit signs as it.
    // Checked before `verify` stores anything, so a served group with somebody else's seat (an envelope may name any
    // group id) is never pinned; `verify` still proves the binding.
    const auto assertOwnSeat = [&] {
        if (keytree::GroupKeyResolver::ownUserId(group) != connection.getImpl()->getMyUserId(group.contextId)) {
            throw GroupDataIntegrityException("the caller was served somebody else's seat");
        }
    };
    assertOwnSeat();
    const keytree::TreeVerifier::Environment environment = treeEnvironment(serverApi, connection, group.id);
    try {
        treeVerifier.verify(group, scope, environment);
    } catch (const EndpointGroupException&) {
        // A torn read, or a concurrent read that pinned a newer state while this answer was in flight: a fresh read
        // settles both, and a real attack fails the second check too.
        group = serverApi.groupGet(model).group;
        if (!keytree::GroupKeyResolver::ownUserId(group).has_value()) {
            throw GroupDataIntegrityException("the caller was served no seat");
        }
        assertOwnSeat();
        treeVerifier.verify(group, scope, environment);
    }
    return GroupRead{.verified = VerifiedGroup(std::move(group)), .unseated = {}};
}
