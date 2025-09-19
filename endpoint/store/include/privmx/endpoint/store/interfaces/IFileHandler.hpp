/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILEHANDLER_INTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILEHANDLER_INTERFACE_HPP_

#include <cstdint>
#include <string>
#include <privmx/endpoint/core/Buffer.hpp>
#include "privmx/endpoint/store/interfaces/IHashList.hpp"
#include "privmx/endpoint/store/StoreTypes.hpp"
namespace privmx {
namespace endpoint {
namespace store {

class IFileHandler
{
public:
    virtual uint64_t size() = 0;
    virtual void seekg(const uint64_t pos) = 0;
    virtual void seekp(const uint64_t pos) = 0;
    virtual core::Buffer read(const size_t length) = 0;
    virtual void write(const core::Buffer& chunk, bool truncate = false) = 0;
    virtual void close() = 0;
    virtual void sync(const FileMeta& fileMeta, const store::FileDecryptionParams& newParms, const core::DecryptedEncKey& fileEncKey) = 0;
    virtual void flush() = 0;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILEHANDLER_INTERFACE_HPP_
