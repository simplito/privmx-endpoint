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

ReleaseGate::Verdict ReleaseGate::check(const std::string&, const Released&, std::uint64_t, std::uint64_t) {
    return Verdict::Ok;
}

void ReleaseGate::record(const std::string&, const Released&) {}

std::optional<ReleaseGate::Released> ReleaseGate::unresolved(const std::string&, std::uint64_t, std::uint64_t) {
    return std::nullopt;
}

const ReleaseGate::Released* ReleaseGate::openLocked(const std::string&, std::uint64_t, std::uint64_t) {
    return nullptr;
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
