/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/*****    "reimplements" privmx-endpoint/crypto/driver   *****/

#include <memory>
#include <string>
#include <vector>
#include <tuple>

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"
#include "CryptoProviderFromDriver.hpp"


#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ripemd.h>

#include <Poco/ByteOrder.h>


namespace privmx {
namespace cryptoservice {

uint32_t  CryptoProviderFromDriver::version() const { return 0; }

std::string  CryptoProviderFromDriver::name() const { 
    return std::string("reimplementation of privmx-endpoint/crypto/driver"); 
}

Bytes CryptoProviderFromDriver::randomBytes(size_t len)
{
    Bytes buffer(len);
    if (RAND_priv_bytes(reinterpret_cast<unsigned char*>(buffer.data()), len) != 1) {
        throw PrivmxDriverCryptoException("randomBytes: Random generator fail");
    }
    return buffer;
}

Bytes CryptoProviderFromDriver::digestConfStr(const char *config, BytesView data)
{
    std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)>
        evp_md(EVP_MD_fetch(NULL, config, NULL), EVP_MD_free);
    if (evp_md.get() == NULL) {
        throw PrivmxDriverCryptoException("Digest: Unable to fetch protocol implementation");
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>
        ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (ctx.get() == NULL) {
        throw PrivmxDriverCryptoException("Digest: Unable to set digest context");
    }
    if (!EVP_DigestInit_ex2(ctx.get(), evp_md.get(), NULL)) {
        throw PrivmxDriverCryptoException("Digest: Message digest initialization failed");
    }
    if (!EVP_DigestUpdate(ctx.get(), data.data(), data.size())) {
        throw PrivmxDriverCryptoException("Digest: Message digest update failed");
    }
    unsigned int len;
    unsigned char res[EVP_MAX_MD_SIZE];
    if (!EVP_DigestFinal_ex(ctx.get(), res, &len)) {
        throw PrivmxDriverCryptoException("Digest: Message digest finalization failed.");
    }
    Bytes result(res, res+len);
    return result;
}

Bytes CryptoProviderFromDriver::digest(Hash alg, BytesView data) 
{
    switch (alg)
    {
    case Hash::Sha1:
        return digestConfStr("SHA1", data);
    case Hash::Sha256:
        return digestConfStr("SHA256", data);
    case Hash::Sha512:
        return digestConfStr("SHA512", data);
    // case Hash::Ripemd160:
    //     return digestConfStr("RIPEMD160", data);
    // case Hash::Hash160:
    //     return digestConfStr("RIPEMD160", digestConfStr("SHA256", data));
    default:
        throw PrivmxDriverCryptoException("Digest: Unknown protocol");
        break;
    }
}

Bytes CryptoProviderFromDriver::hmacConfStr(const char *config,  BytesView key, BytesView data)
{
    std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> 
        evp_mac(EVP_MAC_fetch(NULL, "HMAC", NULL), EVP_MAC_free);
    if (evp_mac.get() == NULL) {
        throw PrivmxDriverCryptoException("HMAC: Unable to fetch protocol implementation");
    }
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> 
        ctx(EVP_MAC_CTX_new(evp_mac.get()), EVP_MAC_CTX_free);
    if (ctx.get() == NULL) {
        throw PrivmxDriverCryptoException("HMAC: Unable to set digest context");
    }
    std::string digest(config);
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", digest.data(), 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_MAC_init(ctx.get(), reinterpret_cast<const unsigned char*>(key.data()), 
        key.size(), params)) {
        throw PrivmxDriverCryptoException("HMAC: Message digest initialization failed");
    }
    if (!EVP_MAC_update(ctx.get(), reinterpret_cast<const unsigned char*>(data.data()), 
        data.size())) {
        throw PrivmxDriverCryptoException("HMAC: Message digest update failed");
    }
    size_t len = EVP_MAC_CTX_get_mac_size(ctx.get());
    uint8_t res[len];
    if (!EVP_MAC_final(ctx.get(), reinterpret_cast<unsigned char*>(res), &len, len)) {
        throw PrivmxDriverCryptoException("HMAC: Message digest finalization failed.");
    }
    Bytes result(res, res+len);
    return result;
}

Bytes CryptoProviderFromDriver::hmac(Hash alg, BytesView key, BytesView data) 
{
    switch (alg)
    {
    case Hash::Sha1:
        return hmacConfStr("SHA1", key, data);
    case Hash::Sha256:
        return hmacConfStr("SHA256", key, data);
    case Hash::Sha512:
        return hmacConfStr("SHA512", key, data);
    // case Hash::Ripemd160:
    //     return hmacConfStr("RIPEMD160", key, data);
    // case Hash::Hash160:
    //     return hmacConfStr("RIPEMD160", key, hmacConfStr("SHA256", key, data));
    default:
        throw PrivmxDriverCryptoException("HMAC: Unknown protocol");
        break;
    }
}

Bytes CryptoProviderFromDriver::encryptConfStr(const char *alg, const bool padding, 
        BytesView key, BytesView iv, BytesView plaintext) 
{
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> 
            cipher(EVP_CIPHER_fetch(NULL, alg, NULL), EVP_CIPHER_free);
    if (cipher.get() == NULL) {
        throw PrivmxDriverCryptoException("Encrypt: Unable to fetch protocol implementation");
    }
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> 
            ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    EVP_CIPHER_CTX* raw_ctx = ctx.get();
    if (raw_ctx == NULL) {
        throw PrivmxDriverCryptoException("Encrypt: Unable to set encryption context");
    }
    EVP_CIPHER_CTX_init(raw_ctx);
    if (EVP_EncryptInit_ex(raw_ctx, cipher.get(), NULL, key.data(), iv.data()) != 1) {
        throw PrivmxDriverCryptoException("Encrypt: Message encryption initialization failed");
    }
    if (!padding && EVP_CIPHER_CTX_set_padding(raw_ctx, 0) != 1) {
        throw PrivmxDriverCryptoException("Encrypt: Message encryption padding failed");
    }
    std::vector<unsigned char> buf(plaintext.size() + EVP_CIPHER_block_size(cipher.get()));
    int buf_len = 0;
    if (EVP_EncryptUpdate(raw_ctx, buf.data(), &buf_len, plaintext.data(), plaintext.size()) != 1) {
        throw PrivmxDriverCryptoException("Encrypt: Message encryption update failed");
    }
    int final_len = 0;
    if (EVP_EncryptFinal_ex(raw_ctx, buf.data() + buf_len, &final_len) != 1) {
        throw PrivmxDriverCryptoException("Encrypt: Message encryption finalization failed.");
    }
    buf_len += final_len;
    EVP_CIPHER_CTX_cleanup(raw_ctx);
    Bytes result(buf.begin(), buf.begin()+buf_len);
    return result;
}

Bytes CryptoProviderFromDriver::encryptAeadConfStr(const char *alg, BytesView aad, 
        BytesView key, BytesView iv, BytesView plaintext) 
{
    const size_t DEFAULT_TAG_LEN = 16;
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> 
            cipher(EVP_CIPHER_fetch(NULL, alg, NULL), EVP_CIPHER_free);
    if (cipher.get() == NULL) {
        throw PrivmxDriverCryptoException("AES AEAD Encrypt: Unable to fetch protocol implementation");
    }
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) { 
        throw PrivmxDriverCryptoException("AES AEAD Encrypt: Unable to set encryption context");
    }
    if (EVP_EncryptInit_ex(ctx.get(), cipher.get(), NULL, key.data(), iv.data()) != 1) {
        throw PrivmxDriverCryptoException("AES AEAD Encrypt: Message encryption initialization failed");
    }
    std::vector<unsigned char> buf(plaintext.size());
    int buf_len = 0;
    int extra_buf_len = 0;
    if (aad.size() > 0) {
        if (EVP_EncryptUpdate(ctx.get(), NULL, &extra_buf_len, aad.data(), aad.size()) != 1) {
            throw PrivmxDriverCryptoException("AES AEAD Encrypt: Message encryption AAD update failed");    
        }
    }
    if (EVP_EncryptUpdate(ctx.get(), buf.data() + buf_len, &extra_buf_len, plaintext.data(), plaintext.size()) != 1) {
        throw PrivmxDriverCryptoException("AES AEAD Encrypt: Message encryption update failed");
    }
    buf_len += extra_buf_len;
    if (EVP_EncryptFinal_ex(ctx.get(), buf.data() + buf_len, &extra_buf_len) != 1) {
        throw PrivmxDriverCryptoException("AES AEAD Encrypt: Message encryption finalization failed.");
    }
    buf_len += extra_buf_len;
    
    unsigned char tagbuf[DEFAULT_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, DEFAULT_TAG_LEN, tagbuf) != 1) {
        throw PrivmxDriverCryptoException("AES AEAD Encrypt: Tag extraction failed");
    }
    EVP_CIPHER_CTX_cleanup(ctx.get());
    // copy buf and tag
    Bytes result(buf.begin(), buf.begin()+buf_len);
    result.reserve(buf_len + DEFAULT_TAG_LEN);
    result.insert(result.end(), tagbuf, tagbuf + DEFAULT_TAG_LEN);
    return result;
}


Bytes CryptoProviderFromDriver::encrypt(const SymParams& opt, BytesView plaintext)
{
    switch (opt.cipher)
    {
    case SymAlg::Aes256Cbc:
        return encryptConfStr("AES-256-CBC", true, opt.key, opt.iv, plaintext);
    case SymAlg::Aes256CbcNoPad:
        return encryptConfStr("AES-256-CBC", false, opt.key, opt.iv, plaintext);
    case SymAlg::Aes256Ecb:
        return encryptConfStr("AES-256-ECB", false, opt.key, opt.iv, plaintext);
    case SymAlg::Aes256Gcm:
        return encryptAeadConfStr("AES-256-GCM", opt.aad, opt.key, opt.iv, plaintext);
    default:
        throw PrivmxDriverCryptoException("Symmetric Encryption: Unknown protocol");
        break;
    }
}

Bytes CryptoProviderFromDriver::decryptConfStr(const char *alg, const bool padding, 
        BytesView key, BytesView iv, BytesView ciphertext) {
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipher(EVP_CIPHER_fetch(NULL, alg, NULL), EVP_CIPHER_free);
    if (cipher.get() == NULL) {
        throw PrivmxDriverCryptoException("Decrypt: Unable to fetch protocol implementation");
    }
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    EVP_CIPHER_CTX* raw_ctx = ctx.get();
    if (raw_ctx == NULL) {
        throw PrivmxDriverCryptoException("Decrypt: Unable to set decryption context");
    }
    EVP_CIPHER_CTX_init(raw_ctx);
    if (EVP_DecryptInit_ex(raw_ctx, cipher.get(), NULL, key.data(), iv.data()) != 1) {
        throw PrivmxDriverCryptoException("Decrypt: Message decryption initialization failed");
    }
    if (!padding && EVP_CIPHER_CTX_set_padding(raw_ctx, 0) != 1) {
        throw PrivmxDriverCryptoException("Decrypt: Message decryption padding failed");    
    }
    std::vector<unsigned char> buf(ciphertext.size() + EVP_CIPHER_block_size(cipher.get()));
    int buf_len = 0;
    if (EVP_DecryptUpdate(raw_ctx, buf.data(), &buf_len, ciphertext.data(), ciphertext.size()) != 1) {
        throw PrivmxDriverCryptoException("Decrypt: Message decryption update failed");    
    }
    int final_len = 0;
    if (EVP_DecryptFinal_ex(raw_ctx, buf.data() + buf_len, &final_len) != 1) {
        throw PrivmxDriverCryptoException("Decrypt: Message decryption finalization failed.");    
    }
    buf_len += final_len;
    EVP_CIPHER_CTX_cleanup(raw_ctx);
    Bytes result(buf.begin(), buf.begin()+buf_len);
    return result;
}

Bytes CryptoProviderFromDriver::decryptAeadConfStr(const char *alg, BytesView aad, 
        BytesView key, BytesView iv, BytesView ciphertextWithTag) {            
    const size_t EXPECTED_TAG_LEN = 16;
    if(ciphertextWithTag.size() <= EXPECTED_TAG_LEN) {
        throw PrivmxDriverCryptoException("AES AEAD Decrypt: wrong tag size");
    }
    size_t data_len = ciphertextWithTag.size() - EXPECTED_TAG_LEN;
    BytesView ciphertext(ciphertextWithTag.begin(),ciphertextWithTag.begin()+data_len);
    BytesView tag(ciphertextWithTag.begin()+data_len,ciphertextWithTag.end());

    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> 
            cipher(EVP_CIPHER_fetch(NULL, alg, NULL), EVP_CIPHER_free);
    if (cipher.get() == NULL) {
        throw PrivmxDriverCryptoException("AES AEAD Decrypt: Unable to fetch protocol implementation");
    }
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> 
            ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (ctx.get() == NULL) {
        throw PrivmxDriverCryptoException("AES AEAD Decrypt: Unable to set decryption context");
    }

    std::vector<unsigned char> buf(ciphertext.size());
    int buf_len = 0;
    int extra_buf_len = 0;
    if (EVP_DecryptInit_ex(ctx.get(), cipher.get(), NULL, key.data(), iv.data()) != 1) {
        throw PrivmxDriverCryptoException("AES AEAD Decrypt: Message decryption initialization failed");
    }
    if (aad.size() > 0) {
        if (EVP_DecryptUpdate(ctx.get(), NULL, &extra_buf_len, aad.data(), aad.size()) != 1) {
            throw PrivmxDriverCryptoException("AES AEAD Decrypt: Message decryption AAD update failed");
        }
    }
    if (EVP_DecryptUpdate(ctx.get(), buf.data() + buf_len, &extra_buf_len, ciphertext.data(), ciphertext.size()) != 1) {
        throw PrivmxDriverCryptoException("AES AEAD Decrypt: Message decryption update failed");
    }
    buf_len += extra_buf_len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data()) != 1) {
        throw PrivmxDriverCryptoException("AES AEAD Decrypt: Setting tag failed");
    }
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), buf.data() + buf_len, &extra_buf_len) != 1) {
        throw PrivmxDriverCryptoException("AES AEAD Decrypt: Message decryption finalization failed.");
    }
    buf_len += extra_buf_len;
    EVP_CIPHER_CTX_cleanup(ctx.get());
    Bytes result(buf.begin(), buf.begin()+buf_len);
    return result;
}

Bytes CryptoProviderFromDriver::decrypt(const SymParams& opt, BytesView ciphertext)
{
    switch (opt.cipher)
    {
    case SymAlg::Aes256Cbc:
        return decryptConfStr("AES-256-CBC", true, opt.key, opt.iv, ciphertext);
    case SymAlg::Aes256CbcNoPad:
        return decryptConfStr("AES-256-CBC", false, opt.key, opt.iv, ciphertext);
    case SymAlg::Aes256Ecb:
        return decryptConfStr("AES-256-ECB", false, opt.key, opt.iv, ciphertext);
    case SymAlg::Aes256Gcm:
        return decryptAeadConfStr("AES-256-GCM", opt.aad, opt.key, opt.iv, ciphertext);
    default:
        throw PrivmxDriverCryptoException("Symmetric Decryption: Unknown protocol");
        break;
    }
}



Bytes CryptoProviderFromDriver::kdf(size_t length, BytesView key, const std::string& label) {
    Poco::UInt32 len = Poco::ByteOrder::toBigEndian((Poco::UInt32)length);
    std::string stringSeed = label + '\0' + std::string((char *)&len, 4);
    const uint8_t* s = reinterpret_cast<const uint8_t*>(stringSeed.data());
    BytesView seed(s, s + label.length() + 1 + 4);
    Bytes k;      // k.size() == 0
    Poco::UInt32 i = 1;
    Bytes result; // result.size() == 0
    while (result.size() < length) {
        Bytes input = k;
        Poco::UInt32 count = Poco::ByteOrder::toBigEndian(i++);
        input.reserve(input.size() + 4 + seed.size());
        input.insert(input.end(),(uint8_t*)&count,((uint8_t*)&count)+4);
        input.insert(input.end(),seed.begin(),seed.end());       
        k = hmac(Hash::Sha256, key, input);
        result.reserve(result.size()+k.size());
        result.insert(result.end(),k.begin(),k.end());
    }
    return Bytes(result.begin(), result.begin()+length);
}

std::tuple<Bytes, Bytes> CryptoProviderFromDriver::getKEM(BytesView key, size_t kelen, size_t kmlen) {
    Bytes kEM = kdf(kelen + kmlen, key, "key expansion");
    return std::make_tuple(Bytes(kEM.begin(),kEM.begin()+kelen), Bytes(kEM.begin()+kelen,kEM.end()));
}

Bytes CryptoProviderFromDriver::aes256CbcHmac256Encrypt(BytesView data, BytesView key32, Bytes iv, size_t taglen) {
    Bytes kE, kM;
    tie(kE, kM) = getKEM(key32);
    if (iv.empty()) {
        iv = hmac(Hash::Sha256, key32, data);
    }
    iv.resize(16);
    Bytes data2(16, 0);
    data2.insert(data2.end(),data.begin(),data.end());
    Bytes cipher = encrypt({SymAlg::Aes256Cbc,kE,iv}, data2);
    Bytes tag = hmac(Hash::Sha256, kM, cipher);
    tag.resize(taglen);
    cipher.reserve(cipher.size()+taglen);
    cipher.insert(cipher.end(),tag.begin(),tag.end());
    return cipher;
}

Bytes CryptoProviderFromDriver::aes256CbcHmac256Decrypt(Bytes data, BytesView key32, size_t taglen) {
    Bytes kE, kM;
    tie(kE, kM) = getKEM(key32);
    Bytes tag(data.begin(), data.begin() + data.size() - taglen);
    data.resize(data.size() - taglen);
    Bytes rtag = hmac(Hash::Sha256, kM, data);
    rtag.resize(taglen);
    if (tag != rtag) {
        throw PrivmxDriverCryptoException("WrongMessageSecurityTagException");
    }
    Bytes iv(data.begin(), data.begin()+16);
    data.erase(data.begin(),data.begin()+16);
    return decrypt({SymAlg::Aes256Cbc,kE,iv}, data);
}

Bytes CryptoProviderFromDriver::pbkdf2(BytesView pass, BytesView salt, int rounds, unsigned int length, const char* hash) {
    std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)> 
            evp_md(EVP_MD_fetch(NULL, hash, NULL), EVP_MD_free);
    if (evp_md.get() == NULL) {
        throw PrivmxDriverCryptoException("PBKDF2: Unable to fetch protocol implementation");
    }
    Bytes result(length, 0);
    const char *pass_as_chars = reinterpret_cast<const char *>(pass.data());
    const unsigned char *salt_as_uchars = reinterpret_cast<const unsigned char *>(salt.data());
    unsigned char *result_as_uchars = reinterpret_cast<unsigned char *>(result.data());
    if (PKCS5_PBKDF2_HMAC(pass_as_chars, pass.size(), salt_as_uchars, salt.size(), 
            rounds, evp_md.get(), length, result_as_uchars) != 1) {
        throw PrivmxDriverCryptoException("PBKDF2: Unable to get hash");
    }
    return result;
}

// Bytes CryptoProviderFromDriver::generateIv(BytesView& key, Poco::Int32 idx) {
//     std::string dataString = "iv" + std::to_string(idx).substr(0, 16);
//     const uint8_t* s = reinterpret_cast<const uint8_t*>(dataString.data());
//     Bytes hash = hmac(Hash::Sha256, key, Bytes(s, s+dataString.length()));
//     hash.resize(16);
//     return hash;
// }

} // cryptoservice
} // privmx

