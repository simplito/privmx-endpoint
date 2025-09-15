/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CHUNKREADER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CHUNKREADER_HPP_

#include <cstdint>
#include <string>
#include <optional>
#include <memory>
#include <privmx/endpoint/core/Buffer.hpp>
#include "privmx/endpoint/store/StoreException.hpp"
#include "privmx/endpoint/store/StoreTypes.hpp"

#include "privmx/endpoint/store/interfaces/IChunkDataProvider.hpp"
#include "privmx/endpoint/store/interfaces/IChunkEncryptor.hpp"
#include "privmx/endpoint/store/interfaces/IHashList.hpp"
#include "privmx/endpoint/store/interfaces/IChunkReader.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class ChunkReader : public IChunkReader
{
public:
    ChunkReader(
        std::shared_ptr<IChunkDataProvider> chunkDataProvider,
        std::shared_ptr<IChunkEncryptor> chunkEncryptor,
        std::shared_ptr<IHashList> hashList,
        const store::FileDecryptionParams& decryptionParams
    );

    virtual size_t filePosToFileChunkIndex(size_t pos) override;
    virtual size_t filePosToPosInFileChunk(size_t pos) override;
    virtual std::string getDecryptedChunk(size_t index) override;
    virtual void sync(const store::FileDecryptionParams& newParms) override;
    virtual void update(int64_t newfileVersion, size_t index) override;
private:
    struct DecryptedChunk {
        std::string decryptedData;
        size_t index;
    };
    std::shared_ptr<IChunkDataProvider> _chunkDataProvider;
    std::shared_ptr<IChunkEncryptor> _chunkEncryptor;
    std::shared_ptr<IHashList> _hashList;
    size_t _chunkSize;
    int64_t _version;
    std::optional<DecryptedChunk> _lastChunk;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CHUNKREADER_HPP_
