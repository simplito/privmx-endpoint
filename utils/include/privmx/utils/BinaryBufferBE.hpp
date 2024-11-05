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
    void writeBool(const bool value);
    void readRawUntilEnd(std::string& value);
    void readBool(bool& value);
    bool isEnd();

    std::stringstream stream;
};

inline void BinaryBufferBE::readOneOctetLengthBuffer(std::string& value) {
    Poco::UInt8 len;
    (*this) >> len;
    readRaw(len, value);
}

inline void BinaryBufferBE::readBool(bool& value) {
    Poco::UInt8 asInt;
    (*this) >> asInt;
    value = asInt == 1;
}


inline void BinaryBufferBE::writeOneOctetLengthBuffer(const std::string& value) {
    Poco::UInt8 len = value.length();
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
