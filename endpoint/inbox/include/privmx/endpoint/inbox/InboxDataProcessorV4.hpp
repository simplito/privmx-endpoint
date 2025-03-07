/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXDATAENCRYPTORV4_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXDATAENCRYPTORV4_HPP_

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/encryptors/DataEncryptorV4.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/inbox/ServerTypes.hpp"
#include <privmx/endpoint/core/TypesMacros.hpp>
#include "privmx/endpoint/inbox/InboxDataHelper.hpp"
#include <privmx/utils/Utils.hpp>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>
#include "privmx/endpoint/core/ExceptionConverter.hpp"


namespace privmx {
namespace endpoint {
namespace inbox {

struct InboxPrivateData {
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
};

struct InboxPrivateDataAsResult : public InboxPrivateData {
    std::string authorPubKey;
    int64_t statusCode;
};

struct InboxPublicData {
    core::Buffer publicMeta;
    std::string inboxEntriesPubKeyBase58DER;
    std::string inboxEntriesKeyId;
};

struct InboxPublicDataAsResult : public InboxPublicData {
    std::string authorPubKey;
    int64_t statusCode;
};

struct InboxPublicViewAsResult : public InboxPublicDataAsResult {
    std::string inboxId;
    int64_t version;
};

struct InboxDataProcessorModel {
    std::string storeId;
    std::string threadId;
    FilesConfig filesConfig;
    InboxPrivateData privateData;
    InboxPublicData publicData;
};

struct InboxDataResult {
    std::string storeId;
    std::string threadId;
    FilesConfig filesConfig;
    InboxPublicDataAsResult publicData;
    InboxPrivateDataAsResult privateData;
    int64_t statusCode;
};

ENDPOINT_CLIENT_TYPE(PrivateDataV4)
    INT64_FIELD(version)
    STRING_FIELD(privateMeta)
    STRING_FIELD(internalMeta)
    STRING_FIELD(authorPubKey)
TYPE_END

ENDPOINT_CLIENT_TYPE(PublicDataV4)
    INT64_FIELD(version)
    STRING_FIELD(publicMeta)
    OBJECT_PTR_FIELD(publicMetaObject)
    STRING_FIELD(authorPubKey)
    STRING_FIELD(inboxPubKey)
    STRING_FIELD(inboxKeyId)
TYPE_END

class InboxDataProcessorV4 {
public:
    server::InboxData packForServer(const InboxDataProcessorModel& plainData,
                                        const crypto::PrivateKey& authorPrivateKey,
                                        const std::string& inboxKey);
    InboxDataResult unpackAll(const server::InboxData& encryptedData,
                                const std::string& inboxKey);

    InboxPublicDataAsResult unpackPublicOnly(const Poco::Dynamic::Var& publicData);

private:
    InboxPublicDataAsResult unpackPublic(const Poco::Dynamic::Var& publicData);
    InboxPrivateDataAsResult unpackPrivate(const server::InboxData& encryptedData, const std::string& inboxKey);
    void validateVersion(const Poco::Dynamic::Var& data);
    core::DataEncryptorV4 _dataEncryptor;
};

}  // namespace inbox
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_INBOX_INBOXDATAENCRYPTORV4_HPP_