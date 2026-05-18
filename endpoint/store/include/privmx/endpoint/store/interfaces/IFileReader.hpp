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

#include "privmx/endpoint/store/StoreTypes.hpp"
#include <cstdint>
#include <optional>
#include <string>

namespace privmx {
namespace endpoint {
namespace store {

class IFileReader {
public:
    virtual ~IFileReader() = default;
    virtual std::string read(uint64_t pos, uint64_t length) = 0;
    virtual void sync(const store::FileDecryptionParams& newParms) = 0;
};

} // namespace store
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILEREADER_INTERFACE_HPP_