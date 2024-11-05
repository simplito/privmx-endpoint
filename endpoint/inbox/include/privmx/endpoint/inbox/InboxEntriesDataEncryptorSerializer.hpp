/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXENTRIESDATAENCRYPTORSERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXENTRIESDATAENCRYPTORSERIALIZER_HPP_

#include <string>
#include <Poco/SharedPtr.h>

#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/Utils.hpp>

namespace privmx {
namespace endpoint {
namespace inbox {
struct InboxEntryPublicData {
    std::string userPubKey;
    bool keyPreset;
    std::string usedInboxKeyId;
};

struct InboxEntryPrivateData {
    std::string filesMetaKey;
    std::string text;
};

struct InboxEntrySendModel {
    InboxEntryPublicData publicData;
    InboxEntryPrivateData privateData;
};

struct InboxEntryPublicDataResult : public InboxEntryPublicData {
    int64_t statusCode;
};

struct InboxEntryDataResult {
    InboxEntryPublicData publicData;
    InboxEntryPrivateData privateData;
    int64_t statusCode;
};

struct InboxEntryResult : public InboxEntryDataResult {
    std::string storeId;
    std::vector<std::string> filesIds;                
};

class InboxEntriesDataEncryptorSerializer {
public:
    using Ptr = Poco::SharedPtr<InboxEntriesDataEncryptorSerializer>;

    InboxEntriesDataEncryptorSerializer();
    std::string packMessage(InboxEntrySendModel data, privmx::crypto::PrivateKey &userPriv, privmx::crypto::PublicKey &inboxPub);
    InboxEntryDataResult unpackMessage(std::string &serializedBase64, privmx::crypto::PrivateKey &inboxPriv);
    InboxEntryPublicDataResult unpackMessagePublicOnly(std::string &serializedBase64);

};

} // inbox
} //endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_INBOXENTRIESDATAENCRYPTORSERIALIZER_HPP_