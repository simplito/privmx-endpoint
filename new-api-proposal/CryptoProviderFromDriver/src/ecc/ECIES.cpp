/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <string>

#include "Utils.hpp"
#include "ECIES.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

using namespace std;

ECIES::ECIES(const PrivateKey& private_key, const PublicKey& public_key) {
    string secret = private_key.derive(public_key);
    // _shared_key = Crypto::sha512(secret);
    _shared_key = NewCrypto::digest(Hash::Sha512,secret);
    _private_enc_key = private_key.getPrivateEncKey();
}

string ECIES::encrypt(const string& data) const {
    // string iv = Crypto::hmacSha256(_private_enc_key, data).substr(0, 16);
    string iv = NewCrypto::hmac(Hash::Sha256,_private_enc_key, data).substr(0, 16);
    string M = getM();
    string E = getE();
    // string c = iv + Crypto::aes256CbcPkcs7Encrypt(data, E, iv);
    string c = iv + NewCrypto::encrypt({SymAlg::Aes256Cbc, E, iv}, data);
    // return c + Crypto::hmacSha256(M, c).substr(0, 4);
    return c + NewCrypto::hmac(Hash::Sha256,M, c).substr(0, 4);
}

string ECIES::decrypt(const string& enc_buf) const {
    string c = enc_buf.substr(0, enc_buf.length() - 4);
    string d = enc_buf.substr(enc_buf.length() - 4, 4);
    string M = getM();
    // string d2 = Crypto::hmacSha256(M, c).substr(0, 4);
    string d2 =  NewCrypto::hmac(Hash::Sha256, M, c).substr(0, 4);
    if (d != d2) {
        // throw InvalidChecksumException();
        throw std::runtime_error("ECIES: InvalidChecksumException");
    }
    string E = getE();
    // return Crypto::aes256CbcPkcs7Decrypt(c.substr(16), E, c.substr(0, 16));
    return NewCrypto::encrypt({SymAlg::Aes256Cbc, E, c.substr(0, 16)}, E);
}

} // ecc
} // cryptoservice
} // privmx