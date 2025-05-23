#ifndef _PRIVMX_ENDPOINT_CRYPTO_INTERFACE_API_
#define _PRIVMX_ENDPOINT_CRYPTO_INTERFACE_API_

#include <Pson/pson.h>
#include <privmx/endpoint/core/cinterface/core.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CryptoApi CryptoApi;

int privmx_endpoint_newCryptoApi(CryptoApi** outPtr);
int privmx_endpoint_freeCryptoApi(CryptoApi* ptr);
int privmx_endpoint_execCryptoApi(CryptoApi* ptr, int method, const pson_value* args, pson_value** res);

typedef struct ExtKey ExtKey;

int privmx_endpoint_newExtKey(ExtKey** outPtr);
int privmx_endpoint_freeExtKey(ExtKey* ptr);
int privmx_endpoint_execExtKey(ExtKey* ptr, int method, const pson_value* args, pson_value** res);

#ifdef __cplusplus
}
#endif

#endif // _PRIVMX_ENDPOINT_CRYPTO_INTERFACE_API_
