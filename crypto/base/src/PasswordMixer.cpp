#include <cmath>
#include <Poco/JSON/Object.h>
#include <Poco/Types.h>

#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/OpenSSLUtils.hpp>
#include <privmx/crypto/PasswordMixer.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/crypto/Crypto.hpp>


using namespace privmx;
using namespace privmx::crypto;
using namespace privmx::utils;
using namespace std;
using namespace Poco;
using namespace Poco::JSON;
using Poco::Dynamic::Var;

string PasswordMixer::mix(const string& password, const Var& data) {
    Object::Ptr obj = data.extract<Object::Ptr>();
    string algorithm = obj->getValue<string>("algorithm");
    string hash = obj->getValue<string>("hash");
    Int32 version = obj->getValue<Int32>("version");
    Int32 rounds = obj->getValue<Int32>("rounds");
    Int32 length = obj->getValue<Int32>("length");
    if (algorithm != "PBKDF2") {
        throw UnsupportedAlgorithmException("'" + algorithm + "'");
    }
    if (hash != "SHA512") {
        throw UnsupportedHashAlgorithmException("'" + hash + "'");
    }
    if (version != 1) {
        throw UnsupportedVersionException("'" + to_string(version) + "'");
    }
    string salt = Base64::toString(obj->getValue<string>("salt"));
    if (salt.length() != 16 || length != 16) {
        throw IncorrectParamsException("salt: " + salt + ", length: " + to_string(length));
    }
    return Crypto::pbkdf2(password, salt, rounds, length, "SHA512");
}

std::tuple<std::string, Poco::JSON::Object::Ptr> PasswordMixer::generatePbkdf2(const std::string &password) {
    static const int keylen = 16;
    string result(keylen, 0);
    auto salt {crypto::Crypto::randomBytes(16)};
    
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    
    float randNum {static_cast <float> (rand()) / static_cast <float> (RAND_MAX)};
    int rounds {4000 + std::floor(randNum * 1000)};
    result = Crypto::pbkdf2(password, salt, rounds, keylen, "SHA512");

    Poco::JSON::Object::Ptr data = new Poco::JSON::Object();
    data->set("algorithm", std::string("PBKDF2"));
    data->set("hash", std::string("SHA512"));
    data->set("length", 16);
    data->set("rounds", rounds);
    data->set("salt", salt);
    data->set("version", 1);
    return {result, data};
}

std::string PasswordMixer::serializeData(Poco::JSON::Object::Ptr data) {
    auto copy = privmx::utils::Utils::jsonObjectDeepCopy(data);
    copy->set("salt", utils::Base64::from(data->getValue<std::string>("salt")));
    return utils::Utils::stringify(copy);
}