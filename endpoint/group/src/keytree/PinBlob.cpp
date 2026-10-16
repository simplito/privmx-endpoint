/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include "privmx/endpoint/group/keytree/PinBlob.hpp"

#include <algorithm>
#include <set>
#include <stdexcept>
#include <vector>

#include <privmx/endpoint/core/BigEndian.hpp>
#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint::group::keytree;
namespace be = privmx::endpoint::core::bigendian;
using Pin = TreeVerifier::Pin;
using PinSet = TreeVerifier::PinSet;
using Planes = std::array<std::int64_t, 3>;

namespace {

constexpr std::uint8_t ROSTER = 1;
constexpr std::uint8_t NODES = 2;
constexpr std::uint8_t FORKED = 4;

std::uint64_t counter(std::int64_t value) {
    return value < 0 ? 0 : static_cast<std::uint64_t>(value);
}

std::int64_t signedCounter(std::uint64_t value) {
    if (value > static_cast<std::uint64_t>(INT64_MAX)) {
        throw std::out_of_range("counter");
    }
    return static_cast<std::int64_t>(value);
}

void putSet(std::string& out, const std::set<std::string>& values) {
    be::putU32(out, static_cast<std::uint32_t>(values.size()));
    for (const std::string& value : values) {
        be::putLp(out, value);
    }
}

std::string record(const std::string& groupId, const Pin& pin, const Planes& planes, bool full) {
    std::string out;
    be::putLp(out, groupId);
    be::putLp(out, pin.contextId);
    be::putU64(out, pin.seq);
    be::putLp(out, pin.digest);
    be::putU64(out, pin.date);
    be::putU64(out, pin.keyVersion);
    be::putLp(out, pin.groupPubKey);
    be::putU64(out, pin.rosterVersion);
    be::putLp(out, pin.roster.hash);
    be::putLp(out, pin.rules.creator);
    be::putLp(out, pin.rules.update);
    be::putLp(out, pin.rules.rotateKeys);
    be::putLp(out, pin.rules.updatePolicy);
    be::putLp(out, pin.rules.ownerCanBeRemovedFromManagers);
    be::putLp(out, pin.rules.hash);
    be::putLp(out, pin.treeHash);
    be::putU64(out, pin.refusedSeq);
    be::putU64(out, pin.seenAt);
    for (const std::int64_t value : planes) {
        be::putU64(out, counter(value));
    }
    be::putU8(out, static_cast<std::uint8_t>((full ? ROSTER | NODES : 0) | (pin.forked ? FORKED : 0)));
    if (full) {
        putSet(out, pin.roster.users);
        putSet(out, pin.roster.managers);
        be::putU32(out, static_cast<std::uint32_t>(pin.generations.size()));
        for (const auto& [node, generation] : pin.generations) {
            be::putU32(out, node);
            be::putU32(out, generation);
        }
    }
    return out;
}

std::set<std::string> readSet(be::Reader& in) {
    std::set<std::string> values;
    const std::uint32_t count = in.u32();
    for (std::uint32_t i = 0; i < count; ++i) {
        values.insert(in.lp());
    }
    return values;
}

const Pin* find(const std::map<std::string, Pin>& pins, const std::string& groupId) {
    const auto it = pins.find(groupId);
    return it == pins.end() ? nullptr : &it->second;
}

Planes planesOf(const PinSet& pins, const std::string& groupId) {
    const auto it = pins.planes.find(groupId);
    return it == pins.planes.end() ? Planes{0, 0, 0} : it->second;
}

} // namespace

std::string PinBlob::encode(const PinSet& pins) {
    std::set<std::string> groups;
    for (const auto& [groupId, pin] : pins.tree) {
        groups.insert(groupId);
    }
    for (const auto& [groupId, planes] : pins.planes) {
        groups.insert(groupId);
    }
    struct Entry {
        std::string compact;
        std::string full; // empty when there is no roster to keep
        std::uint64_t seenAt = 0;
        bool upgraded = false;
    };
    std::map<std::string, Entry> entries;
    std::size_t total = 4;
    const Pin none;
    for (const std::string& groupId : groups) {
        const Pin* pin = find(pins.tree, groupId);
        const Pin& value = pin != nullptr ? *pin : none;
        Entry entry;
        entry.compact = record(groupId, value, planesOf(pins, groupId), false);
        if (value.seq > 0 && value.hasRoster) {
            entry.full = record(groupId, value, planesOf(pins, groupId), true);
        }
        entry.seenAt = value.seenAt;
        total += entry.compact.size();
        entries.emplace(groupId, std::move(entry));
    }
    if (total > BUDGET) {
        LOG_WARN("[pins] the pin blob exceeds its budget with compact records only: ", std::to_string(total))
    }
    std::vector<Entry*> byRecency;
    for (auto& [groupId, entry] : entries) {
        if (!entry.full.empty()) {
            byRecency.push_back(&entry);
        }
    }
    std::stable_sort(byRecency.begin(), byRecency.end(), [](const Entry* a, const Entry* b) {
        return a->seenAt > b->seenAt;
    });
    for (Entry* entry : byRecency) {
        const std::size_t grown = total - entry->compact.size() + entry->full.size();
        if (grown <= BUDGET) {
            entry->upgraded = true;
            total = grown;
        }
    }
    std::string body;
    body.reserve(total);
    be::putU32(body, static_cast<std::uint32_t>(entries.size()));
    for (const auto& [groupId, entry] : entries) {
        body += entry.upgraded ? entry.full : entry.compact;
    }
    return body;
}

std::optional<PinSet> PinBlob::decode(const std::string& body) {
    try {
        be::Reader in(body);
        PinSet pins;
        std::string previous;
        const std::uint32_t count = in.u32();
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::string groupId = in.lp();
            if (i > 0 && groupId <= previous) {
                return std::nullopt;
            }
            previous = groupId;
            Pin pin;
            pin.contextId = in.lp();
            pin.seq = in.u64();
            pin.digest = in.lp();
            pin.date = in.u64();
            pin.keyVersion = in.u64();
            pin.groupPubKey = in.lp();
            pin.rosterVersion = in.u64();
            pin.roster.hash = in.lp();
            pin.rules.creator = in.lp();
            pin.rules.update = in.lp();
            pin.rules.rotateKeys = in.lp();
            pin.rules.updatePolicy = in.lp();
            pin.rules.ownerCanBeRemovedFromManagers = in.lp();
            pin.rules.hash = in.lp();
            pin.treeHash = in.lp();
            pin.refusedSeq = in.u64();
            pin.seenAt = in.u64();
            Planes planes{};
            for (std::int64_t& value : planes) {
                value = signedCounter(in.u64());
            }
            const std::uint8_t flags = in.u8();
            if ((flags & ~(ROSTER | NODES | FORKED)) != 0 || ((flags & NODES) != 0 && (flags & ROSTER) == 0)) {
                return std::nullopt;
            }
            pin.forked = (flags & FORKED) != 0;
            pin.hasRoster = (flags & ROSTER) != 0;
            if (pin.hasRoster) {
                pin.roster.users = readSet(in);
                pin.roster.managers = readSet(in);
            }
            if ((flags & NODES) != 0) {
                const std::uint32_t nodes = in.u32();
                for (std::uint32_t n = 0; n < nodes; ++n) {
                    const std::uint32_t node = in.u32();
                    pin.generations[node] = in.u32();
                }
            }
            if (pin.seq == 0) {
                // Plane-only or lost-race-only: nothing of the tree.
                Pin bare;
                bare.refusedSeq = pin.refusedSeq;
                bare.seenAt = pin.seenAt;
                pin = bare;
            }
            if (pin.seq > 0 || pin.refusedSeq > 0) {
                pins.tree.emplace_hint(pins.tree.end(), groupId, std::move(pin));
            }
            if (planes != Planes{0, 0, 0}) {
                pins.planes.emplace_hint(pins.planes.end(), groupId, planes);
            }
        }
        if (!in.done()) {
            return std::nullopt;
        }
        return pins;
    } catch (const std::out_of_range&) {
        return std::nullopt;
    }
}

PinBlob::Case PinBlob::decide(const Pin* mine, const Pin* stored) {
    const Pin* m = mine != nullptr && mine->seq > 0 ? mine : nullptr;
    const Pin* r = stored != nullptr && stored->seq > 0 ? stored : nullptr;
    if (r == nullptr) {
        return Case::TakeMine; // a
    }
    if (m == nullptr) {
        return Case::TakeStored; // b
    }
    if (m->forked || r->forked || m->contextId != r->contextId) {
        return Case::Fork; // c
    }
    const std::pair<std::uint64_t, std::string> atR{r->seq, r->digest};
    const std::pair<std::uint64_t, std::string> atM{m->seq, m->digest};
    if (atM == atR) {
        return Case::Same; // d
    }
    if (!m->synced.has_value()) {
        return Case::TakeStored; // e: taken by first contact here; the next read walks forward from R
    }
    if (m->unlinked) {
        return Case::Pending; // f
    }
    if (m->synced.value() == atR) {
        return Case::TakeMine; // g
    }
    if (m->synced.value() == atM && r->seq != m->seq) {
        return r->seq > m->seq ? Case::TakeStored : Case::TakeMine; // h1, h2 (the slot went back)
    }
    if (r->seq == m->seq) {
        return Case::Fork; // i
    }
    return Case::Unlinked; // j
}

PinSet PinBlob::mergeForSave(const PinSet& mine, const PinSet& stored) {
    std::set<std::string> groups;
    for (const PinSet* side : {&mine, &stored}) {
        for (const auto& [groupId, pin] : side->tree) {
            groups.insert(groupId);
        }
        for (const auto& [groupId, planes] : side->planes) {
            groups.insert(groupId);
        }
    }
    PinSet merged;
    for (const std::string& groupId : groups) {
        const Pin* m = find(mine.tree, groupId);
        const Pin* r = find(stored.tree, groupId);
        Pin kept;
        switch (decide(m, r)) {
        case Case::TakeMine:
            if (m != nullptr) {
                kept = *m;
            }
            break;
        case Case::Same:
            kept = *m;
            if (!kept.hasRoster && r->hasRoster) {
                kept.roster = r->roster;
                kept.hasRoster = true;
            }
            for (const auto& [node, generation] : r->generations) {
                std::uint32_t& value = kept.generations[node];
                value = std::max(value, generation);
            }
            break;
        case Case::Fork:
            kept = *r;
            kept.forked = true;
            break;
        default: // TakeStored, Pending, Unlinked
            kept = *r;
            break;
        }
        for (const Pin* side : {m, r}) {
            if (side != nullptr) {
                kept.refusedSeq = std::max(kept.refusedSeq, side->refusedSeq);
                kept.seenAt = std::max(kept.seenAt, side->seenAt);
            }
        }
        if (kept.seq > 0 || kept.refusedSeq > 0) {
            merged.tree.emplace(groupId, std::move(kept));
        }
        const Planes a = planesOf(mine, groupId);
        const Planes b = planesOf(stored, groupId);
        const Planes planes{std::max(a[0], b[0]), std::max(a[1], b[1]), std::max(a[2], b[2])};
        if (planes != Planes{0, 0, 0}) {
            merged.planes.emplace(groupId, planes);
        }
    }
    return merged;
}
