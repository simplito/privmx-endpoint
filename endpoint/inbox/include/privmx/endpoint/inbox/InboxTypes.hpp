/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXTYPES_HPP_

#include <string>

#include "privmx/endpoint/inbox/ServerTypes.hpp"
#include "privmx/endpoint/core/CoreTypes.hpp"

namespace privmx {
namespace endpoint {
namespace inbox {


struct InboxPublicViewData : public core::DecryptedVersionedData {
    std::string authorPubKey;
    core::Buffer publicMeta;
    std::string inboxEntriesPubKeyBase58DER;
    std::string inboxEntriesKeyId;
    std::string inboxId;
    int64_t version;
};

// V4

struct InboxPrivateDataV4 {
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
};

struct InboxPrivateDataV4AsResult : public InboxPrivateDataV4, public core::DecryptedVersionedData {
    std::string authorPubKey;
};

struct InboxPublicDataV4 {
    core::Buffer publicMeta;
    std::string inboxEntriesPubKeyBase58DER;
    std::string inboxEntriesKeyId;
};

struct InboxPublicDataV4AsResult : public InboxPublicDataV4, public core::DecryptedVersionedData {
    std::string authorPubKey;
};

struct InboxDataProcessorModelV4 {
    std::string storeId;
    std::string threadId;
    FilesConfig filesConfig;
    InboxPrivateDataV4 privateData;
    InboxPublicDataV4 publicData;
};

struct InboxDataResultV4 : public core::DecryptedVersionedData {
    std::string storeId;
    std::string threadId;
    FilesConfig filesConfig;
    InboxPublicDataV4AsResult publicData;
    InboxPrivateDataV4AsResult privateData;
};

// V5

struct InboxPrivateDataV5 {
    core::Buffer privateMeta;
    core::Buffer internalMeta;
    core::DataIntegrityObject dio;
};

struct InboxPrivateDataV5AsResult : public InboxPrivateDataV5, public core::DecryptedVersionedData {
    std::string authorPubKey;
};

struct InboxPublicDataV5 {
    core::Buffer publicMeta;
    std::string inboxEntriesPubKeyBase58DER;
    std::string inboxEntriesKeyId;
};

struct InboxPublicDataV5AsResult : public InboxPublicDataV5, public core::DecryptedVersionedData {
    std::string authorPubKey;
};

struct InboxDataProcessorModelV5 {
    std::string storeId;
    std::string threadId;
    FilesConfig filesConfig;
    InboxPrivateDataV5 privateData;
    InboxPublicDataV5 publicData;
};

struct InboxDataResultV5 : public core::DecryptedVersionedData {
    std::string storeId;
    std::string threadId;
    FilesConfig filesConfig;
    InboxPublicDataV5AsResult publicData;
    InboxPrivateDataV5AsResult privateData;
};


} // inbox
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_INBOXTYPES_HPP_
