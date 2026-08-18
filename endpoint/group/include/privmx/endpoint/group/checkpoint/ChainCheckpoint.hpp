/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_CHECKPOINT_CHAINCHECKPOINT_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_CHECKPOINT_CHAINCHECKPOINT_HPP_

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <shared_mutex>
#include <string>

namespace privmx {
namespace endpoint {
namespace group {
namespace checkpoint {

/**
 * A trust-on-first-use anchor into one group's verified history chain, for **one group**.
 *
 * `GroupDataSchemaMapper::assertDataIntegrity` proves manager authority transitively from genesis, which makes
 * the first verification of a group unavoidable — but a server that already earned that trust once shouldn't
 * make the client re-buy it on every subsequent read. This anchor is what lets it skip straight to verifying
 * only the entries above the point it last verified: the last-verified entry's index, the sha256 of its signed
 * DIO (the chain link every entry above it must trace back through), and the manager/user sets and epoch state
 * committed at that entry (needed to resume the chain-link, authorization, and epoch-monotonicity checks exactly
 * where they left off).
 *
 * Unlike `TreeKeyCache`, losing this is not free: it is a security anchor, not a bandwidth optimisation — a
 * server that reads it can't retroactively rewrite an already-verified prefix without the rewrite's hash
 * cascading up to break the very entry that anchors here (see the module's "Uwagi" in EP-10). Advancing it is
 * therefore one-directional: `advance()` only accepts a candidate that reaches *further* than what's already
 * stored, so a shorter, still-validly-signed response (e.g. a rollback attempt) can never move it backward.
 *
 * Reachable from the app thread and from event-executor threads at once, hence the lock — same shape as
 * `TreeKeyCache`. The mutex is not recursive: every public method takes it and touches the state directly.
 */
class ChainCheckpoint {
public:
    struct Snapshot {
        /** Number of entries verified as of this checkpoint — equals `groupInfo.data.size()` at that time. */
        int64_t verifiedVersion = 0;
        /** hex(sha256(encData.dio)) of the checkpoint entry — the anchor every entry above it must chain into. */
        std::string lastEntryDioHashHex;
        /** membership.managers as committed by the checkpoint entry. */
        std::set<std::string> verifiedManagers;
        /** membership.users as committed by the checkpoint entry. */
        std::set<std::string> verifiedUsers;
        /** membership.keyVersion as committed by the checkpoint entry — needed to resume epoch monotonicity. */
        int64_t keyVersionAtCheckpoint = 0;
        /** membership.groupPubKey as committed by the checkpoint entry — needed to resume epoch monotonicity. */
        std::string groupPubKeyAtCheckpoint;
    };

    /** The stored snapshot, if any. By value: a reference would outlive the lock. */
    std::optional<Snapshot> get() const;

    /**
     * Stores `candidate` only if it reaches further than what's already stored (or nothing is stored yet).
     *
     * A no-op otherwise — in particular, a candidate verified from a shorter server response (a length
     * regression, e.g. a rollback attempt that this layer doesn't itself reject) never overwrites a checkpoint
     * that has already seen further.
     */
    void advance(const Snapshot& candidate);

private:
    mutable std::shared_mutex _mutex;
    std::optional<Snapshot> _snapshot;
};

/**
 * The per-group checkpoints for one connection.
 *
 * Scoping lives here rather than inside `ChainCheckpoint` for the same reason as `TreeKeyCacheRegistry`: the id
 * is known at the schema-mapper boundary and nowhere deeper, and nothing inside a single checkpoint is keyed by
 * group.
 *
 * Invalidation **detaches** a store instead of clearing it, so it's safe to drop a group's checkpoint while
 * another thread is mid-verification of it: the verifier holds a `shared_ptr` and finishes writing into what is
 * now a private orphan, which dies with the call. Clearing a shared store in place could instead let an
 * in-flight verification write a stale-but-still-monotonic snapshot back in right after the drop.
 */
class ChainCheckpointRegistry {
public:
    /** The checkpoint for one group, created on first use. Never null. */
    std::shared_ptr<ChainCheckpoint> get(const std::string& groupId);

    /** The checkpoint for one group if it already exists, without creating one. For tests and diagnostics. */
    std::shared_ptr<ChainCheckpoint> tryGet(const std::string& groupId) const;

    /** Detaches one group's checkpoint. Handles already taken stay valid; they just stop being shared. */
    void drop(const std::string& groupId);

    /** Detaches every checkpoint. */
    void dropAll();

    /** Number of groups with a live checkpoint. For tests and diagnostics. */
    std::size_t groupCount() const;

private:
    mutable std::shared_mutex _mutex;
    std::map<std::string, std::shared_ptr<ChainCheckpoint>> _stores;
};

} // namespace checkpoint
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_CHECKPOINT_CHAINCHECKPOINT_HPP_
