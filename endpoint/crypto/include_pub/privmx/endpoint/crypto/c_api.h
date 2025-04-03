/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_CRYPTO_C_API_H_
#define _PRIVMXLIB_ENDPOINT_CRYPTO_C_API_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    privmx_CryptoApi_Create = 0,
    privmx_CryptoApi_SignData = 1,
    privmx_CryptoApi_GeneratePrivateKey = 2,
    privmx_CryptoApi_DerivePrivateKey = 3,
    privmx_CryptoApi_DerivePrivateKey2 = 4,
    privmx_CryptoApi_DerivePublicKey = 5,
    privmx_CryptoApi_GenerateKeySymmetric = 6,
    privmx_CryptoApi_EncryptDataSymmetric = 7,
    privmx_CryptoApi_DecryptDataSymmetric = 8,
    privmx_CryptoApi_ConvertPEMKeytoWIFKey = 9,
    privmx_CryptoApi_VerifySignature = 10,
} privmx_CryptoApi_Method;

#ifdef __cplusplus
}
#endif

#endif // _PRIVMXLIB_ENDPOINT_CRYPTO_C_API_H_
