/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_RELEASEGATE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_RELEASEGATE_HPP_

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace privmx {
namespace endpoint {
namespace core {

// m2 (A5-F3): at most one unresolved released statement per chain key. A statement the bridge may have applied
// while answering with an error must not be followed by a different one at the same prevDigest, or the bridge holds
// two valid links by one committer: a fork it chose. Resolved lazily: an entry is gone once the caller's pin reaches
// its seq or its window has passed. Callers serialise check + record per key.
class ReleaseGate {
public:
    struct Released {
        std::uint64_t seq = 0;
        std::string prevDigest;
        std::string digest;
        std::uint64_t date = 0; // the signed date; the window runs from it (N-1 may date ahead of the clock)
        bool yields = false;    // background self-update: lets a non-yielding statement through, nothing else
    };
    enum class Verdict {
        Ok,
        Stale,
        Held
    };

    explicit ReleaseGate(std::uint64_t windowMs);
    // Stale: next.seq <= pinnedSeq. Held: an open entry at the same prevDigest with another digest, unless the
    // entry yields and `next` does not. Ok otherwise; the same digest again (a resend) is always Ok.
    Verdict check(const std::string& key, const Released& next, std::uint64_t now, std::uint64_t pinnedSeq);
    // Keeps the newer of the stored and the incoming entry by `newer` (the order a persisted merge uses too).
    void record(const std::string& key, const Released& next);
    std::optional<Released> unresolved(const std::string& key, std::uint64_t now, std::uint64_t pinnedSeq);
    // Total order: (seq, !yields, date, digest); a full tie is the same entry. At one seq a non-yielding entry always
    // wins, so a merge never leaves only a yielding entry for a prevDigest a non-yielding statement was released at.
    static bool newer(const Released& a, const Released& b);
    // Injective operation key: lp(kind) || lp(part)*, lp = u32 big-endian length || bytes. No separator a user id
    // could contain makes two different operations equal.
    static std::string opKey(const std::string& kind, const std::vector<std::string>& parts = {});

private:
    // The entry, unless the pin passed it or its window closed (then erased). Under `_mutex`.
    const Released* openLocked(const std::string& key, std::uint64_t now, std::uint64_t pinnedSeq);

    const std::uint64_t _windowMs;
    std::mutex _mutex;
    std::map<std::string, Released> _released;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_RELEASEGATE_HPP_
