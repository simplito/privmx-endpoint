#include <memory>
#include <gmpxx.h>
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>

#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/PasswordMixer.hpp>
#include <privmx/crypto/SRP.hpp>
#include <privmx/crypto/SrpLogic.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace privmx::utils;
using namespace std;
using namespace Poco;
using namespace Poco::JSON;
using Poco::Dynamic::Var;

void SRP::initialize(const string& I, const string& password, Int32 tickets) {
    this->_I = I;
    this->_password = password;
    this->_tickets = tickets;
    this->_is_initialized = true;
}

Var SRP::validateSrpInit(const Var& packet) {
    if (_I.empty() || _password.empty()) {
        throw InvalidHandshakeStateException();
    }
    Object::Ptr obj = packet.extract<Object::Ptr>();
    _srp_data.session_id = obj->getValue<string>("sessionId");
    string s = Hex::toString(obj->getValue<string>("s"));
    mpz_class B(obj->getValue<string>("B"), 16);
    mpz_class N(obj->getValue<string>("N"), 16);
    mpz_class g(obj->getValue<string>("g"), 16);
    mpz_class k(obj->getValue<string>("k"), 16);
    Parser parser;
    Var login_data = parser.parse(obj->getValue<string>("loginData"));
    if (B % N == 0) {
        throw InvalidBNException();
    }
    mpz_class a = SrpLogic::get_a();
    mpz_class A = SrpLogic::get_A(g, N, a);
    _srp_data.mixed = PasswordMixer::mix(_password, login_data);
    mpz_class x = SrpLogic::get_x(s, _I, Base64::from(_srp_data.mixed));
    mpz_class v = SrpLogic::get_v(g, N, x);
    mpz_class u = SrpLogic::get_u(A, B, N);
    mpz_class S = SrpLogic::getClient_S(B, k, v, a, u, x, N);
    mpz_class M1 = SrpLogic::get_M1(A, B, S, N);
    _M2 = SrpLogic::get_M2(A, M1, S, N);
    _K = SrpLogic::get_K(S, N);
    unique_ptr<char> A_hex(mpz_get_str(NULL, 16, A.get_mpz_t()));
    unique_ptr<char> M1_hex(mpz_get_str(NULL, 16, M1.get_mpz_t()));
    Object::Ptr result = new Object();
    result->set("type", "srp_exchange");
    result->set("A", addPadding(A_hex.get()));
    result->set("M1", addPadding(M1_hex.get()));
    result->set("sessionId", _srp_data.session_id);
    result->set("tickets", _tickets);
    return result;
}

string SRP::validateSrpExchange(const Var& packet) {
    if (_M2 == 0 || _K.empty()) {
        throw InvalidHandshakeStateException();
    }
    Object::Ptr obj = packet.extract<Object::Ptr>();
    mpz_class M2_2(obj->getValue<string>("M2"), 16);
    if (_M2 != M2_2) {
        throw InvalidM2Exception();
    }
    string result = _K;
    _K = string();
    return result;
}

void SRP::clear() {
    _is_initialized = false;
    _I = string();
    _password = string();
    _tickets = 0;
    _M2 = 0;
    _K = string();
    _srp_data = SrpData();
}

string SRP::addPadding(const string& x) {
    if (x.size() % 2 == 1) {
        return '0' + x;
    }
    return x;
}
