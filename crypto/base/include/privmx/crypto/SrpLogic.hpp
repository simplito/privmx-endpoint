/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_SRPLOGIC_HPP_
#define _PRIVMXLIB_CRYPTO_SRPLOGIC_HPP_

#include <string>
#include <tuple>
#include <gmpxx.h>

namespace privmx {
namespace crypto {

class SrpLogic {
public:
    static mpz_class get_a();
    static mpz_class get_A(const mpz_class& g, const mpz_class& N, const mpz_class& a);
    static mpz_class get_x(const std::string& s, const std::string& I, const std::string& P);
    static std::string H(const std::string& data);
    static mpz_class HBN(const std::string& data);
    static std::string PAD(const mpz_class& x, const mpz_class& N);
    static mpz_class get_k(const mpz_class& g, const mpz_class& N);
    static mpz_class get_v(const mpz_class& g, const mpz_class& N, const mpz_class& x);
    static mpz_class get_u(const mpz_class& A, const mpz_class& B, const mpz_class& N);
    static mpz_class getClient_S(const mpz_class& B, const mpz_class& k, const mpz_class& v, const mpz_class& a, const mpz_class& u, const mpz_class& x, const mpz_class& N);
    static mpz_class get_M1(const mpz_class& A, const mpz_class& B, const mpz_class& S, const mpz_class& N);
    static mpz_class get_M2(const mpz_class& A, const mpz_class& M1, const mpz_class& S, const mpz_class& N);
    static std::string get_K(const mpz_class& S, const mpz_class& N);
    
    static std::tuple<std::string, mpz_class> srpRegister(const mpz_class& N, const mpz_class& g, const std::string& I, const std::string& P, const std::string& s);

};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_SRPLOGIC_HPP_
