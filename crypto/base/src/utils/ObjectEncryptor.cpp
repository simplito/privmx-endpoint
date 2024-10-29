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
