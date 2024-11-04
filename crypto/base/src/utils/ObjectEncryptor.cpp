/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/utils/ObjectEncryptor.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx::crypto;
using namespace std;
using namespace Poco::JSON;

ObjectEncryptor::ObjectEncryptor(const string& key, const PrivmxEncryptOptions& encrypt_options, bool signed_opt)
        : _key(key), _encrypt_options(encrypt_options), _signed(signed_opt) {}

string ObjectEncryptor::encrypt(Object::Ptr obj) {
    auto buff = utils::Utils::stringify(obj);
    return CryptoPrivmx::privmxEncrypt(_encrypt_options, buff, _key);
}

Object::Ptr ObjectEncryptor::decrypt(const string& encrypted) {
    auto buff = CryptoPrivmx::privmxDecrypt(_signed, encrypted, _key);
    return utils::Utils::parseJsonObject(buff);
}
