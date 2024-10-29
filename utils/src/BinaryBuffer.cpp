#include <Poco/StreamCopier.h>

#include <privmx/utils/BinaryBuffer.hpp>

using namespace privmx;
using namespace privmx::utils;
using namespace std;
using namespace Poco;

string BinaryBuffer::str() {
    return stream.str();
}

streamsize BinaryBuffer::copyFromStream(istream& istream) {
    return StreamCopier::copyStreamUnbuffered(istream, stream);
}

streamsize BinaryBuffer::copyToStream(ostream& ostream) {
    return StreamCopier::copyStreamUnbuffered(stream, ostream);
}

std::streamsize BinaryBuffer::copyFrom(BinaryBuffer& buffer) {
    return copyFromStream(buffer.stream);
}
