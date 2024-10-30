#ifndef _PRIVMXLIB_UTILS_BINARYBUFFER_HPP_
#define _PRIVMXLIB_UTILS_BINARYBUFFER_HPP_

#include <sstream>
#include <Poco/BinaryReader.h>
#include <Poco/BinaryWriter.h>

namespace privmx {
namespace utils {

class BinaryBuffer : public Poco::BinaryReader, public Poco::BinaryWriter
{
public:
    BinaryBuffer() : Poco::BinaryReader(stream), Poco::BinaryWriter(stream) {}
    std::string str();
    std::streamsize copyFromStream(std::istream& istream);
    std::streamsize copyToStream(std::ostream& ostream);
    std::streamsize copyFrom(BinaryBuffer& buffer);

    std::stringstream stream;
};

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_BINARYBUFFER_HPP_
