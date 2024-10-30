#include <emscripten/emscripten.h>
#include <emscripten/val.h>

#include <privmx/crypto/ecc/ECC.hpp>
#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/emscripten/ecc/ECCImpl.hpp>
#include <privmx/crypto/emscripten/Bindings.hpp>
#include <privmx/crypto/CryptoConfig.hpp>

using namespace privmx;
using namespace privmx::crypto::emscriptenimpl;
using namespace std;

#ifdef PRIVMX_DEFAULT_CRYPTO_EMSCRIPTEN
privmx::crypto::ECCImpl::Ptr privmx::crypto::ECCImpl::genPair() {
    return privmx::crypto::emscriptenimpl::ECCImpl::genPair();
}

privmx::crypto::ECCImpl::Ptr privmx::crypto::ECCImpl::fromPublicKey(const string& public_key) {
    return privmx::crypto::emscriptenimpl::ECCImpl::fromPublicKey(public_key);
}

privmx::crypto::ECCImpl::Ptr privmx::crypto::ECCImpl::fromPrivateKey(const std::string& private_key) {
    return privmx::crypto::emscriptenimpl::ECCImpl::fromPrivateKey(private_key);
}
#endif

ECCImpl::Ptr ECCImpl::genPair() {
    emscripten::val name { emscripten::val::u8string("ecc_genPair") };
    emscripten::val params { emscripten::val::null() };

    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on genPair");
    }

    std::string priv_key { result["buff"]["privateKey"].as<std::string>() };
    std::string pub_key { result["buff"]["publicKey"].as<std::string>() };

    return new ECCImpl(priv_key, pub_key, true);
}

ECCImpl::Ptr ECCImpl::fromPublicKey(const string& public_key) {
    emscripten::val name { emscripten::val::u8string("ecc_fromPublicKey") };
    emscripten::val params { emscripten::val::object() };
    params.set("key", typed_memory_view(public_key.size(), public_key.data())); 

    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on fromPublicKey");
    }
    std::string pub_key { result["buff"]["publicKey"].as<std::string>() };

    return new ECCImpl(std::string(), pub_key, false);
}

ECCImpl::Ptr ECCImpl::fromPrivateKey(const std::string& private_key) {
    emscripten::val name { emscripten::val::u8string("ecc_fromPrivateKey") };
    emscripten::val params { emscripten::val::object() };
    params.set("key", typed_memory_view(private_key.size(), private_key.data())); 

    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on fromPrivateKey");
    }

    std::string priv_key { result["buff"]["privateKey"].as<std::string>() };
    std::string pub_key { result["buff"]["publicKey"].as<std::string>() };

    return new ECCImpl(priv_key, pub_key, true);
}

ECCImpl::ECCImpl() {}

ECCImpl::ECCImpl(const ECCImpl& obj) : _privkey(obj._privkey), _pubkey(obj._pubkey), _has_priv(obj._has_priv) {}

ECCImpl::ECCImpl(ECCImpl&& obj) : _privkey(move(obj._privkey)), _pubkey(obj._pubkey), _has_priv(move(obj._has_priv)) {}

ECCImpl::ECCImpl(const std::string& privkey, const std::string& pubkey, bool has_priv)
        : _privkey(privkey), _pubkey(pubkey), _has_priv(has_priv) {}

ECCImpl& ECCImpl::operator=(const ECCImpl& obj) {
    _has_priv = obj._has_priv;
    _privkey = obj._privkey;
    _pubkey = obj._pubkey;
    return *this;
}

ECCImpl& ECCImpl::operator=(ECCImpl&& obj) {
    _has_priv = move(obj._has_priv);
    _privkey = move(obj._privkey);
    _pubkey = move(obj._pubkey);
    return *this;
}

string ECCImpl::getPublicKey(bool compact) const {
    return _pubkey;
}

PointImpl::Ptr ECCImpl::getPublicKey2() const {
    return new PointImpl(_pubkey);
}

string ECCImpl::getPrivateKey() const {
    return _privkey;
}

BNImpl::Ptr ECCImpl::getPrivateKey2() const {
    return new BNImpl(_privkey);
}

string ECCImpl::sign(const string& data) const {
    emscripten::val name { emscripten::val::u8string("ecc_sign") };
    emscripten::val params { emscripten::val::object() };
    params.set("privateKey", typed_memory_view(_privkey.size(), _privkey.data()));
    params.set("data", emscripten::typed_memory_view(data.size(), data.data()));

    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on sign");
    }

    std::string sig { result["buff"].as<std::string>() };
    return sig;
}

ECCImpl::Signature ECCImpl::sign2(const string& data) const {
    emscripten::val name { emscripten::val::u8string("ecc_sign") };
    emscripten::val params { emscripten::val::object() };
    params.set("privateKey", typed_memory_view(_privkey.size(), _privkey.data()));
    params.set("data", emscripten::typed_memory_view(data.size(), data.data())); 

    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on sign");
    }

    std::string tmp { result["buff"].as<std::string>() };
    std::string r { tmp.substr(1, 32) };
    std::string s { tmp.substr(33, 32) };
    return {.r = new BNImpl(r), .s = new BNImpl(s)};
}

bool ECCImpl::verify(const std::string& data, const std::string& signature) const {
    emscripten::val name { emscripten::val::u8string("ecc_verify") };
    emscripten::val params { emscripten::val::object() };
    params.set("publicKey", typed_memory_view(_pubkey.size(), _pubkey.data()));
    params.set("data", emscripten::typed_memory_view(data.size(), data.data()));
    params.set("signature", emscripten::typed_memory_view(signature.size(), signature.data())); 

    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on verify");
    }
    bool verified { result["buff"].as<bool>() };
    return verified;
}

bool ECCImpl::verify2(const std::string& data, const ECCImpl::Signature& signature) const {
    emscripten::val name { emscripten::val::u8string("ecc_verify2") };
    emscripten::val params { emscripten::val::object() };
    params.set("data", emscripten::typed_memory_view(data.size(), data.data()));
    params.set("r", emscripten::typed_memory_view(signature.r->toBuffer().size(), signature.r->toBuffer().data())); 
    params.set("s", emscripten::typed_memory_view(signature.s->toBuffer().size(), signature.s->toBuffer().data())); 

    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on verify");
    }
    bool verified { result["buff"].as<bool>() };
    return verified;
}

string ECCImpl::derive(const ECCImpl::Ptr ecc) const {
    emscripten::val name { emscripten::val::u8string("ecc_derive") };
    emscripten::val params { emscripten::val::object() };
    auto pub_key = ecc.cast<ECCImpl>()->_pubkey; // TODO
    params.set("privateKey", typed_memory_view(_privkey.size(), _privkey.data()));
    params.set("publicKey", typed_memory_view(pub_key.size(), pub_key.data()));
    
    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on derive");
    }

    std::string derived { result["buff"].as<std::string>() };
    return derived;
}

string ECCImpl::getOrder() const {
    emscripten::val name { emscripten::val::u8string("ecc_getOrder") };
    emscripten::val params { emscripten::val::null() };
    
    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on getOrder");
    }
    std::string n { result["buff"].as<std::string>() };
    return n;
}

BNImpl::Ptr ECCImpl::getOrder2() const {
    emscripten::val name { emscripten::val::u8string("ecc_getOrder") };
    emscripten::val params { emscripten::val::null() };
    
    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on getOrder");
    }
    std::string n { result["buff"].as<std::string>() };
    return new BNImpl(n);
}

PointImpl::Ptr ECCImpl::getGenerator() const {
    emscripten::val name { emscripten::val::u8string("ecc_getGenerator") };
    emscripten::val params { emscripten::val::null() };
    
    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on getGenerator");
    }
    std::string g { result["buff"].as<std::string>() };
    return new PointImpl(g);
}

BNImpl::Ptr ECCImpl::getEcOrder() const {
    emscripten::val name { emscripten::val::u8string("ecc_getOrder") };
    emscripten::val params { emscripten::val::null() };
    
    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on getOrder");
    }
    std::string n { result["buff"].as<std::string>() };
    return new BNImpl(n);
}

PointImpl::Ptr ECCImpl::getEcGenerator() const {
    emscripten::val name { emscripten::val::u8string("ecc_getGenerator") };
    emscripten::val params { emscripten::val::null() };
    
    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on getGenerator");
    }
    std::string g { result["buff"].as<std::string>() };
    return new PointImpl(g);
}
