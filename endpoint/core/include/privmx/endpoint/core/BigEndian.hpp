/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_CORE_BIGENDIAN_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_BIGENDIAN_HPP_

#include <cstdint>
#include <string>

namespace privmx {
namespace endpoint {
namespace core {

// The byte codec of every signed preimage: big-endian integers, `lp(x)` = u32 length || bytes.
namespace bigendian {

inline void putU8(std::string& out, std::uint8_t value) {
    out.push_back(static_cast<char>(value));
}

inline void putU32(std::string& out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((value >> shift) & 0xFF));
    }
}

inline void putU64(std::string& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((value >> shift) & 0xFF));
    }
}

inline void putLp(std::string& out, const std::string& value) {
    putU32(out, static_cast<std::uint32_t>(value.size()));
    out += value;
}

} // namespace bigendian
} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_BIGENDIAN_HPP_
