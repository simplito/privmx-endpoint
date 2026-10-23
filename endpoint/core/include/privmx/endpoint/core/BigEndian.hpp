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
#include <stdexcept>
#include <string>

namespace privmx {
namespace endpoint {
namespace core {

// The byte codec of every local blob and signed preimage: big-endian integers, `lp(x)` = u32 length || bytes.
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

// Reads what the writers above wrote. Throws std::out_of_range on any read past the end, so a length field cannot
// make a parser read memory it was not given.
class Reader {
public:
    explicit Reader(const std::string& bytes) : _bytes(bytes) {}
    std::uint8_t u8() { return static_cast<std::uint8_t>(take(1)[0]); }
    std::uint32_t u32() { return static_cast<std::uint32_t>(number(4)); }
    std::uint64_t u64() { return number(8); }
    std::string lp() {
        const std::uint32_t length = u32();
        return std::string(take(length), length);
    }
    bool done() const { return _offset == _bytes.size(); }

private:
    const char* take(std::size_t length) {
        if (length > _bytes.size() - _offset) {
            throw std::out_of_range("read past the end");
        }
        const char* at = _bytes.data() + _offset;
        _offset += length;
        return at;
    }
    std::uint64_t number(std::size_t length) {
        const char* at = take(length);
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < length; ++i) {
            value = (value << 8) | static_cast<std::uint8_t>(at[i]);
        }
        return value;
    }

    const std::string& _bytes;
    std::size_t _offset = 0;
};

} // namespace bigendian
} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_BIGENDIAN_HPP_
