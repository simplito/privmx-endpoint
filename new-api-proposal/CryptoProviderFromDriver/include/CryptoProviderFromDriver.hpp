/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_CRYPTOPROVIDERFROMDRIVER_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_CRYPTOPROVIDERFROMDRIVER_HPP_

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"


namespace privmx {
namespace cryptoservice {

class CryptoProviderFromDriver : public privmx::cryptoservice::ICryptoProvider
{
public:
    virtual uint32_t version() const override; 
    virtual std::string name() const override;
    virtual Bytes randomBytes(size_t len) override;
    virtual Bytes digest(Hash alg, BytesView data) override; 
    virtual Bytes hmac(Hash alg, BytesView key, BytesView data) override;
    virtual Bytes encrypt(const SymParams&, BytesView plaintext) override;
    virtual Bytes decrypt(const SymParams&, BytesView ciphertext) override;

protected:
    virtual Bytes digestConfStr(const char *config, BytesView data); 
    virtual Bytes hmacConfStr(const char *config,  BytesView key, BytesView data);
    virtual Bytes encryptConfStr(const char *alg, const bool padding, 
                        BytesView key, BytesView iv, BytesView plaintext);
    virtual Bytes encryptAeadConfStr(const char *alg, BytesView aad, 
                        BytesView key, BytesView iv, BytesView plaintext);
    virtual Bytes decryptConfStr(const char *alg, const bool padding, 
                        BytesView key, BytesView iv, BytesView ciphertext);
    virtual Bytes decryptAeadConfStr(const char *alg, BytesView aad, 
                        BytesView key, BytesView iv, BytesView ciphertext);

private:
    virtual Bytes pbkdf2(BytesView pass, BytesView salt, int rounds, 
                        unsigned int length, const char* hash);
    virtual Bytes kdf(size_t length, BytesView key, const std::string& label);
    virtual std::tuple<Bytes, Bytes> getKEM(BytesView key, size_t kelen = 32, 
                        size_t kmlen = 32);
    // virtual Bytes generateIv(BytesView& key, Poco::Int32 idx); // require Poco
    virtual Bytes aes256CbcHmac256Encrypt(BytesView data, BytesView key32, Bytes iv, 
                        size_t taglen);
    virtual Bytes aes256CbcHmac256Decrypt(Bytes data, BytesView key32, size_t taglen);
};

} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_CRYPTOPROVIDERFROMDRIVER_HPP_