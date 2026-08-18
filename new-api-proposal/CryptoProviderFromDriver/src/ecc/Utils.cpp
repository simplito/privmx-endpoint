/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/* Temporary classes to facilitate rewriting 
    from an old implementation to a new one   */


#include <iterator>
#include <string_view>
#include <vector>

#include <string>
#include <regex>
#include <sstream>

#include <Poco/Base64Encoder.h>
#include <Poco/Base64Decoder.h>
#include <Poco/StreamCopier.h>
#include <Poco/JSON/Parser.h>

#include "Utils.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

/* methods decoding Base64 strings (with use of POCO lib) - begin  */

template<typename Decoder>
inline std::string decodeInline(const std::string& encoded_data) {
    std::istringstream encoded_data_stream(encoded_data);
    std::ostringstream decoded_data_stream;
    Decoder decoder(encoded_data_stream);
    Poco::StreamCopier::copyStreamUnbuffered(decoder, decoded_data_stream);
    return decoded_data_stream.str();
}

template<typename Encoder>
inline std::string encodeInline(const std::string& data_to_encode, int line_length = 0) {
    std::ostringstream encoded_data_stream;
    Encoder encoder(encoded_data_stream);
    encoder.rdbuf()->setLineLength(line_length);
    encoder.write(data_to_encode.data(), data_to_encode.length());
    encoder.close();
    return encoded_data_stream.str();
}

std::string Base64::from(const std::string& data, int line_length) {
    return encodeInline<Poco::Base64Encoder>(data, line_length);
}

std::string Base64::toString(const std::string& base64_data) {
    return decodeInline<Poco::Base64Decoder>(base64_data);
}

bool Base64::is(const std::string& data) {
    std::regex base64Regex("^(?=(.{4})*$)[A-Za-z0-9+/]*={0,2}$");
    return std::regex_match(data, base64Regex);
}

/* methods decoding Base64 strings (with use of POCO lib) - end  */


std::string Utils::fillTo32(const std::string& data) {
    if(data.length() >= 32) {
        return data;
    }
    return std::string(32 - data.length(), 0) + data;
}

std::string Utils::removeEscape(const std::string& data) {
    std::string result = data;
    for (std::string::iterator it = result.begin(); it != result.end(); ++it) {
        if (*it == '\\' && *(it+1) == '/') {
            it = result.erase(it);
        }
    }
    return result;
}

std::string Utils::stringify(const Poco::JSON::Array::Ptr& arr, bool pretty) {
    std::ostringstream stream;
    arr->stringify(stream, pretty ? 4 : 0);
    return Utils::removeEscape(stream.str());
}

std::string Utils::stringify(const Poco::JSON::Object::Ptr& obj, bool pretty) {
    std::ostringstream stream;
    obj->stringify(stream, pretty ? 4 : 0);
    return Utils::removeEscape(stream.str());
}

Poco::Dynamic::Var Utils::parseJson(const std::string& json) {
    Poco::JSON::Parser parser;
    return parser.parse(json);
}

Poco::JSON::Object::Ptr Utils::parseJsonObject(const std::string& json) {
    Poco::JSON::Parser parser;
    return parser.parse(json).extract<Poco::JSON::Object::Ptr>();
}

// NewCrypto class is to be removed in the next commit
// --- to be removed (NewCrypto) - begin ---
ICryptoProvider& NewCrypto::get() { 
    return _provider;
}

std::string NewCrypto::randomBytes(size_t len) {
        Bytes r = _provider.randomBytes(len);
    return std::string(r.begin(),r.end());
}

std::string NewCrypto::digest(Hash alg, const std::string data) {
    Bytes hash = _provider.digest(alg, Bytes(data.begin(), data.end()));
    return std::string(hash.begin(),hash.end());
}

std::string NewCrypto::hmac(Hash alg, const std::string key, const std::string data) {
    Bytes hash = _provider.hmac(alg, Bytes(key.begin(), key.end()), Bytes(data.begin(), data.end()));
    return std::string(hash.begin(),hash.end());
}

std::string NewCrypto::encrypt(const SymParamsString& o, std::string plaintext) {
    Bytes ciphertext = _provider.encrypt(
        {o.cipher, Bytes(o.key.begin(), o.key.end()), 
            Bytes(o.iv.begin(), o.iv.end()), o.aad }, 
            Bytes(plaintext.begin(), plaintext.end()));
    return std::string(ciphertext.begin(),ciphertext.end());
}

std::string NewCrypto::decrypt(const SymParamsString& o, std::string ciphertext) {
    Bytes plaintext = _provider.decrypt(
        {o.cipher, Bytes(o.key.begin(), o.key.end()), 
            Bytes(o.iv.begin(), o.iv.end()), o.aad }, 
            Bytes(ciphertext.begin(), ciphertext.end()));
    return std::string(plaintext.begin(),plaintext.end());
}
// --- to be removed (NewCrypto) - end ---

std::string Utils::b2s(BytesView data) {
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

Bytes Utils::s2b(const std::string& data) {
    const unsigned char* d = reinterpret_cast<const unsigned char*>(data.data());
    return Bytes(d, d+data.size());
}

Bytes Utils::fillTo32b(Bytes& data) {
    if(data.size() < 32) {
        const uint8_t zero = 0;
        // data.reserve(32);
        data.insert(data.begin(), 32 - data.size(), zero);
    }
    return data;
}

} // namespace ecc
} // cryptoservice
} // privmx
