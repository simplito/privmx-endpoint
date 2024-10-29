#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/ecc/ECIES.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace std;

ECIES::ECIES(const PrivateKey& private_key, const PublicKey& public_key) {
    string secret = private_key.derive(public_key);
    _shared_key = Crypto::sha512(secret);
    _private_enc_key = private_key.getPrivateEncKey();
}

string ECIES::encrypt(const string& data) const {
    string iv = Crypto::hmacSha256(_private_enc_key, data).substr(0, 16);
    string M = getM();
    string E = getE();
    string c = iv + Crypto::aes256CbcPkcs7Encrypt(data, E, iv);
    return c + Crypto::hmacSha256(M, c).substr(0, 4);
}

string ECIES::decrypt(const string& enc_buf) const {
    string c = enc_buf.substr(0, enc_buf.length() - 4);
    string d = enc_buf.substr(enc_buf.length() - 4, 4);
    string M = getM();
    string d2 = Crypto::hmacSha256(M, c).substr(0, 4);
    if (d != d2) {
        throw InvalidChecksumException();
    }
    string E = getE();
    return Crypto::aes256CbcPkcs7Decrypt(c.substr(16), E, c.substr(0, 16));
}
