/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

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
