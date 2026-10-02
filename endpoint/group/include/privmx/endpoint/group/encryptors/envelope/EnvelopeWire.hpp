/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_ENVELOPE_ENVELOPEWIRE_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_ENVELOPE_ENVELOPEWIRE_HPP_

#include <cstddef>
#include <cstdint>
#include <string>

namespace privmx {
namespace endpoint {
namespace group {

// Hand-rolled rather than `utils::BinaryBufferBE`: that helper leaves its length octet uninitialized at EOF
// and reads short without complaint, so a three-byte envelope "parses" into garbage. Every read is checked.
class EnvelopeReader {
public:
    // `buf` must outlive the reader — nothing is copied.
    explicit EnvelopeReader(const std::string& buf) : _buf(buf) {}

    std::uint8_t readU8();
    std::uint64_t readU64();
    std::string readField();
    std::string readRest();
    void skip(std::size_t n);

    // Bytes consumed so far — i.e. the header, once the header fields have been read.
    std::string consumed() const { return _buf.substr(0, _pos); }

private:
    void require(std::size_t n) const;

    const std::string& _buf;
    std::size_t _pos = 0;
};

class EnvelopeWriter {
public:
    // Throws above 255 bytes: the wire uses a single length octet, so a silent truncation would produce an
    // envelope that parses cleanly into the wrong thing. Real fields are far below this.
    static void putField(std::string& out, const std::string& value);

    static std::string toBE(std::uint64_t value, int bytes);
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_ENVELOPE_ENVELOPEWIRE_HPP_
