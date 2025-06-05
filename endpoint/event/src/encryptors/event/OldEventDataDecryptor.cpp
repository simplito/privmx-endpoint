/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/event/encryptors/event/OldEventDataDecryptor.hpp"
#include "privmx/endpoint/event/Constants.hpp"
#include "privmx/endpoint/event/EventException.hpp"
#include <privmx/endpoint/core/ExceptionConverter.hpp>


using namespace privmx::endpoint;
using namespace privmx::endpoint::event;

DecryptedContextEventDataV1 OldEventDataDecryptor::decryptV1(const Poco::Dynamic::Var& data, const crypto::PublicKey& authorPublicKey, const std::string& encryptionKey) {
    DecryptedContextEventDataV1 result;
    result.statusCode = 0;
    result.dataStructureVersion = EventDataSchema::Version::VERSION_1;
    try {
        if(data.isString()) {
            result.data = _dataEncryptor.decodeAndDecryptAndVerify(
                data.convert<std::string>(), 
                authorPublicKey,
                encryptionKey
            );
        } else {
            result.statusCode = InvalidEncryptedEventDataVersionException().getCode();
        }
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}
