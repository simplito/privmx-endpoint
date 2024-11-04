/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_BN_HPP_
#define _PRIVMXLIB_CRYPTO_BN_HPP_

#include <string>

#include <privmx/crypto/ecc/BNImpl.hpp>

namespace privmx {
namespace crypto {

class BN
{
public:
    static BN fromBuffer(const std::string& data);
    BN();
    BN(const BN& obj);
    BN(BN&& obj);
    BN(BNImpl::Ptr impl);
    BN& operator=(const BN& obj);
    BN& operator=(BN&& obj);
    operator bool() const;
    bool isEmpty() const;
    std::string toBuffer() const;
    std::size_t getBitsLength() const;
    BN umod(const BN& bn) const;
    bool eq(const BN& bn) const;
    BNImpl::Ptr getImpl() const;

private:
    BNImpl::Ptr _impl;

};

inline BN BN::fromBuffer(const std::string& data) {
    return BN(BNImpl::fromBuffer(data));
}

inline BN::BN() {
    _impl = BNImpl::getDefault();
}

inline BN::BN(const BN& obj) {
    _impl = obj._impl;
}

inline BN::BN(BN&& obj) {
    _impl = obj._impl;
}

inline BN::BN(BNImpl::Ptr impl) {
    _impl = impl;
}

inline BN& BN::operator=(const BN& obj) {
    _impl = obj._impl;
    return *this;
}

inline BN& BN::operator=(BN&& obj) {
    _impl = obj._impl;
    return *this;
}

inline BN::operator bool() const {
    return !_impl->isEmpty();
}

inline bool BN::isEmpty() const {
    return !_impl->isEmpty();
}

inline std::string BN::toBuffer() const {
    return _impl->toBuffer();
}

inline std::size_t BN::getBitsLength() const {
    return _impl->getBitsLength();
}

inline BN BN::umod(const BN& bn) const {
    return BN(_impl->umod(bn._impl));
}

inline bool BN::eq(const BN& bn) const {
    return _impl->eq(bn._impl);
}

inline BNImpl::Ptr BN::getImpl() const {
    return _impl;
}

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_BN_HPP_
