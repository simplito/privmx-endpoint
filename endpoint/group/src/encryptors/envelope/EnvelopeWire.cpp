/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/encryptors/envelope/EnvelopeWire.hpp"

#include "privmx/endpoint/group/GroupException.hpp"

using namespace privmx::endpoint::group;

std::uint8_t EnvelopeReader::readU8() {
    require(1);
    return static_cast<std::uint8_t>(_buf[_pos++]);
}

std::uint64_t EnvelopeReader::readU64() {
    require(8);
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | static_cast<std::uint8_t>(_buf[_pos++]);
    }
    return value;
}

std::string EnvelopeReader::readField() {
    std::size_t len = readU8();
    require(len);
    std::string value = _buf.substr(_pos, len);
    _pos += len;
    return value;
}

std::string EnvelopeReader::readRest() {
    std::string value = _buf.substr(_pos);
    _pos = _buf.size();
    return value;
}

void EnvelopeReader::skip(std::size_t n) {
    require(n);
    _pos += n;
}

void EnvelopeReader::require(std::size_t n) const {
    if (_buf.size() - _pos < n) {
        throw InvalidEnvelopeFormatException("envelope truncated");
    }
}

void EnvelopeWriter::putField(std::string& out, const std::string& value) {
    if (value.size() > 255) {
        throw InvalidEnvelopeFormatException("envelope field exceeds 255 bytes");
    }
    out.push_back(static_cast<char>(value.size()));
    out.append(value);
}

std::string EnvelopeWriter::toBE(std::uint64_t value, int bytes) {
    std::string out(bytes, '\0');
    for (int i = bytes - 1; i >= 0; --i) {
        out[i] = static_cast<char>(value & 0xFF);
        value >>= 8;
    }
    return out;
}
