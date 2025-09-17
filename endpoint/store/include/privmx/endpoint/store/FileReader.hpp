/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILE_READER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILE_READER_HPP_

#include <cstdint>
#include <string>
#include <optional>
#include <memory>
#include "privmx/endpoint/store/interfaces/IFileReader.hpp"
#include "privmx/endpoint/store/interfaces/IChunkReader.hpp"


namespace privmx {
namespace endpoint {
namespace store {

class FileReader : public IFileReader
{
public:
    FileReader (
        std::shared_ptr<IChunkReader> chunkReader,
        const store::FileDecryptionParams& decryptionParams
    );

    virtual std::string read(uint64_t pos, uint64_t length) override;
    virtual void sync(const store::FileDecryptionParams& newParms) override;
private:
    std::shared_ptr<IChunkReader> _chunkReader;
    uint64_t _plainfileSize;
    int64_t _version;
};


} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILE_HANDLER_HPP_
