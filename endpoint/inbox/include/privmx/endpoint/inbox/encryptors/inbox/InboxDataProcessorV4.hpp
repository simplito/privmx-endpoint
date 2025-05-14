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
#include "privmx/endpoint/inbox/InboxTypes.hpp"
#include <privmx/utils/Utils.hpp>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>
#include "privmx/endpoint/core/ExceptionConverter.hpp"


namespace privmx {
namespace endpoint {
namespace inbox {

class InboxDataProcessorV4 {
public:
    server::InboxData packForServer(const InboxDataProcessorModelV4& plainData,
                                        const crypto::PrivateKey& authorPrivateKey,
                                        const std::string& inboxKey);
    InboxDataResultV4 unpackAll(const server::InboxData& encryptedData,
                                const std::string& inboxKey);

    InboxPublicDataV4AsResult unpackPublicOnly(const Poco::Dynamic::Var& publicData);

private:
    InboxPublicDataV4AsResult unpackPublic(const Poco::Dynamic::Var& publicData);
    InboxPrivateDataV4AsResult unpackPrivate(const server::InboxData& encryptedData, const std::string& inboxKey);
    void validateVersion(const Poco::Dynamic::Var& data);
    core::DataEncryptorV4 _dataEncryptor;
};

}  // namespace inbox
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_INBOX_INBOXDATAENCRYPTORV4_HPP_