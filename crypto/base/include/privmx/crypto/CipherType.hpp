#ifndef _PRIVMXLIB_CRYPTO_CIPHERTYPE_HPP_
#define _PRIVMXLIB_CRYPTO_CIPHERTYPE_HPP_

namespace privmx {
namespace crypto {

class CipherType
{
public:
    static const char AES_256_CBC_PKCS7_NO_IV                   = 1;
    static const char AES_256_CBC_PKCS7_WITH_IV                 = 2;
    static const char XTEA_ECB_PKCS7                            = 3;
    static const char AES_256_CBC_PKCS7_WITH_IV_AND_HMAC_SHA256 = 4;
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_CIPHERTYPE_HPP_
