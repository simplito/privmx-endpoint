/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILEREADER_INTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILEREADER_INTERFACE_HPP_

namespace privmx {
namespace endpoint {
namespace store {

class IFileReader
{
public:
    virtual ~IFileReader() = default;
    virtual std::string read(uint64_t pos, size_t length) = 0;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILEREADER_INTERFACE_HPP_