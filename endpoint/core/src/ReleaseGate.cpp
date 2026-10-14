/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/ReleaseGate.hpp"

#include <tuple>

using namespace privmx::endpoint::core;

ReleaseGate::ReleaseGate(std::uint64_t windowMs) : _windowMs(windowMs) {}

ReleaseGate::Verdict ReleaseGate::check(
    const std::string& key,
    const Released& next,
    std::uint64_t now,
    std::uint64_t pinnedSeq
) {
    std::lock_guard<std::mutex> lock(_mutex);
    // Behind the pin: the statement at that seq has landed or lost; P is unreachable either way. This is also what
    // keeps lazy resolution safe once our own statement there landed and its entry was dropped.
    if (next.seq <= pinnedSeq) {
        return Verdict::Stale;
    }
    const Released* open = openLocked(key, now, pinnedSeq);
    if (open != nullptr &&
        open->prevDigest == next.prevDigest &&
        open->digest != next.digest &&
        !(open->yields && !next.yields)) {
        return Verdict::Held;
    }
    return Verdict::Ok;
}

void ReleaseGate::record(const std::string& key, const Released& next) {
    std::lock_guard<std::mutex> lock(_mutex);
    const auto it = _released.find(key);
    if (it == _released.end()) {
        _released.emplace(key, next);
    } else if (newer(next, it->second)) {
        it->second = next;
    }
}

std::optional<ReleaseGate::Released> ReleaseGate::unresolved(
    const std::string& key,
    std::uint64_t now,
    std::uint64_t pinnedSeq
) {
    std::lock_guard<std::mutex> lock(_mutex);
    const Released* open = openLocked(key, now, pinnedSeq);
    return open == nullptr ? std::nullopt : std::optional<Released>(*open);
}

const ReleaseGate::Released* ReleaseGate::openLocked(
    const std::string& key,
    std::uint64_t now,
    std::uint64_t pinnedSeq
) {
    const auto it = _released.find(key);
    if (it == _released.end()) {
        return nullptr;
    }
    // Landed, superseded (the pin passed it) or expired (an honest bridge refuses it by its date by now).
    if (pinnedSeq >= it->second.seq || now >= it->second.date + _windowMs) {
        _released.erase(it);
        return nullptr;
    }
    return &it->second;
}

bool ReleaseGate::newer(const Released& a, const Released& b) {
    return std::make_tuple(a.seq, !a.yields, a.date, a.digest) > std::make_tuple(b.seq, !b.yields, b.date, b.digest);
}

std::string ReleaseGate::opKey(const std::string& kind, const std::vector<std::string>& parts) {
    std::string out;
    const auto lp = [&out](const std::string& field) {
        const auto size = static_cast<std::uint32_t>(field.size());
        for (int shift = 24; shift >= 0; shift -= 8) {
            out.push_back(static_cast<char>((size >> shift) & 0xFF));
        }
        out += field;
    };
    lp(kind);
    for (const std::string& part : parts) {
        lp(part);
    }
    return out;
}
