/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CHUNKREADER_INTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CHUNKREADER_INTERFACE_HPP_

namespace privmx {
namespace endpoint {
namespace store {

class IChunkReader
{
public:
    virtual ~IChunkReader() = default;
    virtual size_t filePosToFileChunkIndex(size_t pos) = 0;
    virtual size_t filePosToPosInFileChunk(size_t pos) = 0;
    virtual std::string getDecryptedChunk(size_t index) = 0;
    virtual void sync(const store::FileDecryptionParams& newParms) = 0;
    virtual void update(int64_t newfileVersion, size_t index) = 0;
};


} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CHUNKREADER_INTERFACE_HPP_