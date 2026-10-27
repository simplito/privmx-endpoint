/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_VERIFIEDGROUP_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_VERIFIEDGROUP_HPP_

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <privmx/endpoint/core/Connection.hpp>

#include "privmx/endpoint/group/ServerApi.hpp"
#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/keytree/TreeVerifier.hpp"

namespace privmx {
namespace endpoint {
namespace group {

struct GroupRead;

// `groupGet` in the default "path" scope, with nothing for anybody else.
server::GroupGetModel pathRead(const std::string& groupId);

// `groupGet` in the "plan" scope: every node record a plan resolves through, plus the departing members' paths
// (`forUserIds`) or seats for the newcomers (`forNewMembers`).
server::GroupGetModel planRead(
    const std::string& groupId,
    std::optional<std::vector<std::string>> forUserIds = std::nullopt,
    std::optional<std::int64_t> forNewMembers = std::nullopt
);

// The connection's UserVerifier and the group's statements, as TreeVerifier reads them.
keytree::TreeVerifier::Environment treeEnvironment(
    ServerApi& serverApi,
    const core::Connection& connection,
    const std::string& groupId
);

// The one reader of VerifiedGroup: reads the group (`model`) and checks the served tree against the commit
// statements before any key from it is used (TreeVerifier). Checks nothing for a group without a supported tree or a
// caller without a seat: there is nothing it could climb, and the callers refuse both. Any failure is re-read once
// and checked again: a torn read, or a concurrent read having pinned a newer state, passes the second time.
// `afterVerify` runs once the answer is in, whatever the check then does (it saves the pins the check moved).
GroupRead readGroup(
    ServerApi& serverApi,
    keytree::TreeVerifier& treeVerifier,
    const core::Connection& connection,
    const server::GroupGetModel& model,
    keytree::TreeVerifier::Scope scope,
    const std::function<void()>& afterVerify
);

// A `groupGet` answer that holds a seat of the caller's and whose tree passed `readGroup`'s check against the commit
// statements, as it left it. Only `readGroup` constructs one; it never changes after that.
class VerifiedGroup {
public:
    const server::GroupInfo& operator*() const { return _group; }
    const server::GroupInfo* operator->() const { return &_group; }
    // Read-only views of the answer pass where a plain one is taken.
    operator const server::GroupInfo&() const { return _group; }

private:
    explicit VerifiedGroup(server::GroupInfo group) : _group(std::move(group)) {}

    server::GroupInfo _group;
    friend GroupRead readGroup(
        ServerApi&,
        keytree::TreeVerifier&,
        const core::Connection&,
        const server::GroupGetModel&,
        keytree::TreeVerifier::Scope,
        const std::function<void()>&
    );
};

// What `readGroup` saw: `verified`, or, for a group without a supported tree or a caller without a seat, the answer
// as served (`unseated`), which nothing checked and no key may come from.
struct GroupRead {
    std::optional<VerifiedGroup> verified;
    server::GroupInfo unseated; // only when `verified` is empty

    const server::GroupInfo& group() const { return verified.has_value() ? **verified : unseated; }
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_VERIFIEDGROUP_HPP_
