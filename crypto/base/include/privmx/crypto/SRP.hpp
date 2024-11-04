/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_SRP_HPP_
#define _PRIVMXLIB_CRYPTO_SRP_HPP_

#include <string>
#include <gmpxx.h>
#include <Poco/Dynamic/Var.h>
#include <Poco/Logger.h>

namespace privmx {
namespace crypto {

struct SrpData {
    std::string mixed = std::string();
    std::string session_id;
};

class SRP {
public:
    void initialize(const std::string& I, const std::string& password, Poco::Int32 tickets);
    bool isInitialized() const { return _is_initialized; }
    Poco::Dynamic::Var validateSrpInit(const Poco::Dynamic::Var& paket);
    std::string validateSrpExchange(const Poco::Dynamic::Var& packet);
    void clear();
    SrpData getSrpData() const { return _srp_data; }
    static std::string addPadding(const std::string& x);
private:

    bool _is_initialized = false;
    std::string _I;
    std::string _password;
    Poco::Int32 _tickets;
    mpz_class _M2 = 0;
    std::string _K = std::string();
    SrpData _srp_data;
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_SRP_HPP_
