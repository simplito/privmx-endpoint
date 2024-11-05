/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/CryptoConfig.hpp>
#ifdef PRIVMX_ENABLE_CRYPTO_OPENSSL
#include <openssl/bn.h>
#include <openssl/err.h>
#endif

#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/OpenSSLUtils.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace std;

string OpenSSLUtils::CaLocation{};

string getError() {
#ifdef PRIVMX_ENABLE_CRYPTO_OPENSSL
    unsigned long e = ERR_get_error();
    if (e == 0) {
        return string();
    }
    char buf[256];
    ERR_error_string(e, buf);
    return string(buf);
#else
    return string();
#endif
}

void OpenSSLUtils::handleErrors(const string& msg){
    string text = "OpenSSL";
    if (!msg.empty()) {
        text.append(" ")
            .append(msg);
    }
    string error = getError();
    if (!error.empty()) {
        text.append(": ")
            .append(error);
    }
    throw OpenSSLException(text);
}
