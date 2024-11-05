/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/SrpLogic.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace std;

mpz_class SrpLogic::get_a() {
    mpz_class a;
    string random_bytes = Crypto::randomBytes(64);
    mpz_import(a.get_mpz_t(), random_bytes.size(), 1, 1, 0, 0, random_bytes.data());
    return a; 
}

mpz_class SrpLogic::get_A(const mpz_class& g, const mpz_class& N, const mpz_class& a) {
    mpz_class A;
    mpz_powm(A.get_mpz_t(), g.get_mpz_t(), a.get_mpz_t(), N.get_mpz_t());
    return A;
}

mpz_class SrpLogic::get_x(const string& s, const string& I, const string& P) {
    string hash = H(I + ":" + P);
    return HBN(s + hash);
}

string SrpLogic::H(const string& data) {
    return Crypto::sha256(data);
}

mpz_class SrpLogic::HBN(const string& data) {
    mpz_class result;
    string hash = H(data);
    mpz_import(result.get_mpz_t(), hash.size(), 1, 1, 0, 0, hash.data());
    return result;
}

string SrpLogic::PAD(const mpz_class& x, const mpz_class& N) {
    size_t N_size = (mpz_sizeinbase(N.get_mpz_t(), 2) + 7) / 8;
    size_t x_size = (mpz_sizeinbase(x.get_mpz_t(), 2) + 7) / 8;
    string result(N_size, 0);
    mpz_export((char *)result.data() + (N_size - x_size), &x_size, 1, 1, 0, 0, x.get_mpz_t());
    return result;
}

mpz_class SrpLogic::get_k(const mpz_class& g, const mpz_class& N) {
    return HBN(PAD(N,N) + PAD(g,N));
}

mpz_class SrpLogic::get_v(const mpz_class& g, const mpz_class& N, const mpz_class& x) {
    mpz_class v;
    mpz_powm(v.get_mpz_t(), g.get_mpz_t(), x.get_mpz_t(), N.get_mpz_t());
    return v;
}

mpz_class SrpLogic::get_u(const mpz_class& A, const mpz_class& B, const mpz_class& N) {
    string data = PAD(A, N) + PAD(B, N);
    return HBN(data);
}

mpz_class SrpLogic::getClient_S(const mpz_class& B, const mpz_class& k, const mpz_class& v, const mpz_class& a, const mpz_class& u, const mpz_class& x, const mpz_class& N) {
    mpz_class S;
    mpz_class bkv = (B - ((v * k) % N)) % N;
    mpz_class aux = a + (u * x);
    mpz_powm(S.get_mpz_t(), bkv.get_mpz_t(), aux.get_mpz_t(), N.get_mpz_t());
    return S;
}

mpz_class SrpLogic::get_M1(const mpz_class& A, const mpz_class& B, const mpz_class& S, const mpz_class& N) {
    return HBN(PAD(A, N) + PAD(B, N) + PAD(S, N));
}

mpz_class SrpLogic::get_M2(const mpz_class& A, const mpz_class& M1, const mpz_class& S, const mpz_class& N) {
    return HBN(PAD(A, N) + PAD(M1, N) + PAD(S, N));
}

std::string SrpLogic::get_K(const mpz_class& S, const mpz_class& N) {
    return H(PAD(S, N));
}

std::tuple<std::string, mpz_class> SrpLogic::srpRegister(const mpz_class& N, const mpz_class& g, const std::string& I, const std::string& P, const std::string& s) {
    auto x = get_x(s, I, P);
    auto v = get_v(g, N, x);
    return {s, v};
}
