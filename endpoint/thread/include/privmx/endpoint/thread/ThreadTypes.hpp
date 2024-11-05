/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_THREADTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_THREADTYPES_HPP_

#include <string>

#include "privmx/endpoint/thread/DynamicTypes.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

struct MessageDataToEncrypt {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::Buffer data;
    std::optional<core::Buffer> internalMeta;
};

struct DecryptedMessageData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::Buffer data;
    std::optional<core::Buffer> internalMeta;
    std::string authorPubKey;
    int64_t statusCode;
};

struct ThreadDataToEncrypt {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
};

struct DecryptedThreadData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
    std::string authorPubKey;
    int64_t statusCode;
};

} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADTYPES_HPP_
