/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXDATAENCRYPTORV5_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXDATAENCRYPTORV5_HPP_

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/encryptors/DataEncryptorV4.hpp"
#include "privmx/endpoint/core/encryptors/DIO/DIOEncryptorV1.hpp"
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

class InboxDataProcessorV5 {
public:
    server::InboxData packForServer(const InboxDataProcessorModelV5& plainData,
                                        const crypto::PrivateKey& authorPrivateKey,
                                        const std::string& inboxKey);
    InboxDataResultV5 unpackAll(const server::InboxData& encryptedData,
                                const std::string& inboxKey);

    InboxPublicDataV5AsResult unpackPublicOnly(const Poco::Dynamic::Var& publicData);

private:
    InboxPublicDataV5AsResult unpackPublic(const Poco::Dynamic::Var& publicData);
    InboxPrivateDataV5AsResult unpackPrivate(const server::InboxData& encryptedData, const std::string& inboxKey);
    core::DataIntegrityObject getDIOAndAssertIntegrity(const server::PrivateDataV5& encryptedPrivateData);
    void assertDataFormat(const server::PrivateDataV5& encryptedPrivateData);
    void assertDataFormat(const server::PublicDataV5& encryptedPublicData);
    void validateVersion(const Poco::Dynamic::Var& data);
    core::DataEncryptorV4 _dataEncryptor;
    core::DIOEncryptorV1 _DIOEncryptor;
};

}  // namespace inbox
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_INBOX_INBOXDATAENCRYPTORV5_HPP_