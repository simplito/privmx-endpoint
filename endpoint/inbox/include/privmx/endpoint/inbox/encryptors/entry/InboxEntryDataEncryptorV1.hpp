/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXENTRYDATAENCRYPTORV1_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXENTRYDATAENCRYPTORV1_HPP_

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>

#include "privmx/endpoint/inbox/InboxTypes.hpp"

namespace privmx {
namespace endpoint {
namespace inbox {

class InboxEntryDataEncryptorV1 {
public:
    std::string encrypt(
        InboxEntrySendModel data,
        privmx::crypto::PrivateKey& userPriv,
        privmx::crypto::PublicKey& inboxPub
    );
    InboxEntryDataResult decrypt(std::string& serializedBase64, privmx::crypto::PrivateKey& inboxPriv);
    InboxEntryPublicDataResult decryptPublicOnly(std::string& serializedBase64);
};

} // namespace inbox
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_INBOXENTRYDATAENCRYPTORV1_HPP_
