/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_BINARYBUFFERBE_HPP_
#define _PRIVMXLIB_UTILS_BINARYBUFFERBE_HPP_

#include <sstream>
#include <Poco/BinaryReader.h>
#include <Poco/BinaryWriter.h>
#include <Poco/Types.h>

#include <privmx/utils/PrivmxExtExceptions.hpp>

namespace privmx {
namespace utils {

class BinaryBufferBE : public Poco::BinaryReader, public Poco::BinaryWriter
{
public:
    BinaryBufferBE() : Poco::BinaryReader(stream, Poco::BinaryReader::BIG_ENDIAN_BYTE_ORDER), Poco::BinaryWriter(stream, Poco::BinaryWriter::BIG_ENDIAN_BYTE_ORDER) {}
    BinaryBufferBE(const std::string& str) : Poco::BinaryReader(stream, Poco::BinaryReader::BIG_ENDIAN_BYTE_ORDER), Poco::BinaryWriter(stream, Poco::BinaryWriter::BIG_ENDIAN_BYTE_ORDER), stream(str) {}
    std::string str() { return stream.str(); }
    void readOneOctetLengthBuffer(std::string& value);
    void writeOneOctetLengthBuffer(const std::string& value);
    void readTwoOctetLengthBuffer(std::string& value);
    void writeTwoOctetLengthBuffer(const std::string& value);
    void writeBool(const bool value);
    void readRawUntilEnd(std::string& value);
    void readBool(bool& value);
    bool isEnd();

    std::stringstream stream;
};

inline void BinaryBufferBE::readOneOctetLengthBuffer(std::string& value) {
    // Both halves used to fail silently on a truncated buffer: at EOF the extraction left `len` uninitialized,
    // and Poco's `readRaw` short-reads without complaint. Together they turned a two-byte buffer into a field
    // of garbage length holding garbage bytes. Callers parse attacker-supplied buffers with this.
    if (available() < 1) {
        throw BinaryBufferTruncatedException();
    }
    Poco::UInt8 len = 0;
    (*this) >> len;
    if (available() < static_cast<std::streamsize>(len)) {
        throw BinaryBufferTruncatedException();
    }
    readRaw(len, value);
}

inline void BinaryBufferBE::readBool(bool& value) {
    Poco::UInt8 asInt;
    (*this) >> asInt;
    value = asInt == 1;
}


inline void BinaryBufferBE::writeOneOctetLengthBuffer(const std::string& value) {
    // One length octet on the wire: a value of 256 would otherwise write a length of 0 and produce a buffer
    // that parses cleanly into something else entirely.
    if (value.length() > 255) {
        throw BinaryBufferFieldTooLongException();
    }
    Poco::UInt8 len = static_cast<Poco::UInt8>(value.length());
    (*this) << len;
    writeRaw(value);
}

/**
 * The same field with a two-octet length, for buffers that carry a public key.
 *
 * A key was 33 bytes when one octet was chosen; a post-quantum identity is 1248, and about 1.7 kB
 * once base58-encoded. Truncation is still refused rather than wrapped, for the reason the one-octet
 * pair gives: callers parse attacker-supplied buffers with this.
 */
inline void BinaryBufferBE::readTwoOctetLengthBuffer(std::string& value) {
    if (available() < 2) {
        throw BinaryBufferTruncatedException();
    }
    Poco::UInt16 len = 0;
    (*this) >> len;
    if (available() < static_cast<std::streamsize>(len)) {
        throw BinaryBufferTruncatedException();
    }
    readRaw(len, value);
}

inline void BinaryBufferBE::writeTwoOctetLengthBuffer(const std::string& value) {
    if (value.length() > 0xFFFF) {
        throw BinaryBufferFieldTooLongException();
    }
    Poco::UInt16 len = static_cast<Poco::UInt16>(value.length());
    (*this) << len;
    writeRaw(value);
}

inline void BinaryBufferBE::writeBool(const bool value) {
    Poco::UInt8 asInt = value ? 1 : 0;
    (*this) << asInt;
}

inline void BinaryBufferBE::readRawUntilEnd(std::string& value) {
    readRaw(available(), value);
}

inline bool BinaryBufferBE::isEnd() {
    if (eof()) return true;
    return available() <= 0;
}

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_BINARYBUFFERBE_HPP_
