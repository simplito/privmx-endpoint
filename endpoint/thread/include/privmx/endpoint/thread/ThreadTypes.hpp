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
#include "privmx/endpoint/core/CoreTypes.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

struct MessageDataToEncryptV4 {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::Buffer data;
    std::optional<core::Buffer> internalMeta;
};

struct MessageDataToEncryptV5 {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::Buffer data;
    std::optional<core::Buffer> internalMeta;
    core::DataIntegrityObject dio;
};

struct DecryptedMessageDataV4 : public core::DecryptedVersionedData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::Buffer data;
    std::optional<core::Buffer> internalMeta;
    std::string authorPubKey;
};

struct DecryptedMessageDataV5 : public core::DecryptedVersionedData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::Buffer data;
    std::optional<core::Buffer> internalMeta;
    std::string authorPubKey;
    core::DataIntegrityObject dio;
};

struct ThreadDataToEncryptV4 {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
};

struct ThreadDataToEncryptV5 {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
    core::DataIntegrityObject dio;
};


struct DecryptedThreadDataV4 : public core::DecryptedVersionedData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
    std::string authorPubKey;
};

struct DecryptedThreadDataV5 : public core::DecryptedVersionedData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
    std::string authorPubKey;
    core::DataIntegrityObject dio;
};

} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADTYPES_HPP_
