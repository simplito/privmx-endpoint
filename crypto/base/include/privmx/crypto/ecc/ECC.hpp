/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_ECC_HPP_
#define _PRIVMXLIB_CRYPTO_ECC_HPP_

#include <functional>
#include <memory>
#include <string>

#include <privmx/crypto/ecc/BN.hpp>
#include <privmx/crypto/ecc/Point.hpp>
#include <privmx/crypto/ecc/ECCImpl.hpp>

namespace privmx {
namespace crypto {

class ECC
{
public:
    struct Signature
    {
        BN r;
        BN s;
    };

    static ECC genPair();
    static ECC fromPublicKey(const std::string& public_key);
    static ECC fromPrivateKey(const std::string& private_key);
    ECC();
    ECC(const ECC& obj);
    ECC(ECC&& obj);
    ECC(ECCImpl::Ptr impl);
    ECC& operator=(const ECC& obj);
    ECC& operator=(ECC&& obj);
    operator bool() const;
    bool isEmpty() const;
    std::string getPublicKey(bool compact = true) const;
    Point getPublicKey2() const;
    std::string getPrivateKey() const;
    BN getPrivateKey2() const;
    std::string sign(const std::string& data) const;
    Signature sign2(const std::string& data) const;
    bool verify(const std::string& data, const std::string& signature) const;
    bool verify2(const std::string& data, const Signature& signature) const;
    std::string derive(const ECC& ecc) const;
    std::string getOrder() const;
    BN getOrder2() const;
    Point getGenerator() const;
    static BN getEcOrder();
    static Point getEcGenerator();
    bool hasPrivate() const;
    ECCImpl::Ptr getImpl() const;

private:
    ECCImpl::Ptr _impl;

};

inline ECC ECC::genPair() {
    return ECC(ECCImpl::genPair());
}

inline ECC ECC::fromPublicKey(const std::string& public_key) {
    return ECC(ECCImpl::fromPublicKey(public_key));
}

inline ECC ECC::fromPrivateKey(const std::string& private_key) {
    return ECC(ECCImpl::fromPrivateKey(private_key));
}

inline ECC::ECC() {
    _impl = ECCImpl::genPair();
}

inline ECC::ECC(const ECC& obj) {
    _impl = obj._impl;
}

inline ECC::ECC(ECC&& obj) {
    _impl = obj._impl;
}

inline ECC::ECC(ECCImpl::Ptr impl) {
    _impl = impl;
}

inline ECC& ECC::operator=(const ECC& obj) {
    _impl = obj._impl;
    return *this;
}

inline ECC& ECC::operator=(ECC&& obj) {
    _impl = obj._impl;
    return *this;
}


inline ECC::operator bool() const {
    return !_impl->isEmpty();
}

inline bool ECC::isEmpty() const {
    return _impl->isEmpty();
}

inline std::string ECC::getPublicKey(bool compact) const {
    return _impl->getPublicKey(compact);
}

inline Point ECC::getPublicKey2() const {
    return Point(_impl->getPublicKey2());
}

inline std::string ECC::getPrivateKey() const {
    return _impl->getPrivateKey();
}

inline BN ECC::getPrivateKey2() const {
    return _impl->getPrivateKey2();
}

inline std::string ECC::sign(const std::string& data) const {
    return _impl->sign(data);
}

inline ECC::Signature ECC::sign2(const std::string& data) const {
    auto res = _impl->sign2(data);
    return {res.r, res.s};
}

inline bool ECC::verify(const std::string& data, const std::string& signature) const {
    return _impl->verify(data, signature);
}

inline bool ECC::verify2(const std::string& data, const Signature& signature) const {
    return _impl->verify2(data, {signature.r.getImpl(), signature.s.getImpl()});
}

inline std::string ECC::derive(const ECC& ecc) const {
    return _impl->derive(ecc.getImpl());
}

inline std::string ECC::getOrder() const {
    return _impl->getOrder();
}

inline BN ECC::getOrder2() const {
    return _impl->getOrder2();
}

inline Point ECC::getGenerator() const {
    return _impl->getGenerator();
}

inline BN ECC::getEcOrder() {
    return BN(ECCImpl::genPair()->getEcOrder());
}

inline Point ECC::getEcGenerator() {
    return Point(ECCImpl::genPair()->getEcGenerator());
}

inline bool ECC::hasPrivate() const {
    return _impl->hasPrivate();
}

inline ECCImpl::Ptr ECC::getImpl() const {
    return _impl;
}

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_ECC_HPP_
