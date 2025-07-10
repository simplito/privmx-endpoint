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
#include <stdlib.h>
#include <privmx/endpoint/core/Buffer.hpp>

namespace privmx {
namespace endpoint {
namespace store {

class IFileHandler
{
public:
    virtual size_t size() = 0;
    virtual void seekg(const size_t pos) = 0;
    virtual void seekp(const size_t pos) = 0;
    virtual core::Buffer read(const size_t length) = 0;
    virtual void write(const core::Buffer& chunk) = 0;
    virtual void truncate() = 0;
    virtual void close() = 0;
    virtual void sync() = 0;
    virtual void flush() = 0;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILEHANDLER_INTERFACE_HPP_
