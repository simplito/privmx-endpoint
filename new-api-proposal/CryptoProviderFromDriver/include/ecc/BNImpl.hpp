/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_BNIMPL_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_BNIMPL_HPP_

#include <functional>
#include <memory>
#include <string>
#include <openssl/bn.h>
#include <Poco/SharedPtr.h>

#include "CoreTypes.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

class BNImpl
{
public:
    // using Ptr = Poco::SharedPtr<BNImpl>;
    using Ptr = std::shared_ptr<BNImpl>;
    // using bn_unique_ptr = std::unique_ptr<privmxDrvEcc_BN, std::function<decltype(privmxDrvEcc_bnFree)>>;
    using bn_unique_ptr = std::unique_ptr<BIGNUM, std::function<decltype(BN_free)>>;

    static BNImpl::Ptr fromBuffer(const std::string& data);
    static BNImpl::Ptr getDefault();
    BNImpl() = default;
    BNImpl(const BNImpl& obj);
    BNImpl(BNImpl&& obj);
    BNImpl(bn_unique_ptr&& bn);
    BNImpl& operator=(const BNImpl& obj);
    BNImpl& operator=(BNImpl&& obj);
    operator bool() const;
    bool isEmpty() const;
    std::string toBuffer() const;
    std::size_t getBitsLength() const;
    BNImpl::Ptr umod(const BNImpl::Ptr bn) const;
    // bool eq(const privmx::crypto::BNImpl::Ptr bn) const override;
    bool eq(const BNImpl::Ptr bn) const;
    // const privmxDrvEcc_BN* getRaw() const;
    const BIGNUM* getRaw() const;

    Bytes toBufferB() const;

private:
    using bn_ctx_unique_ptr = std::unique_ptr<BN_CTX, std::function<decltype(BN_CTX_free)>>;

    static bn_unique_ptr bin2bignum(const std::string& bin);
    static bn_unique_ptr copyBignum(const bn_unique_ptr& bn);
    
    static bn_unique_ptr newBignum();
    static bn_ctx_unique_ptr newBnCtx();

    void validate() const;

    bn_unique_ptr _bn;
};

inline BNImpl::operator bool() const {
    return !isEmpty();
}

inline bool BNImpl::isEmpty() const {
    return !_bn;
}

inline BNImpl::bn_unique_ptr BNImpl::newBignum() {
    BNImpl::bn_unique_ptr bignum(BN_new(), BN_free);
    if (bignum.get() == NULL) {
        // OpenSSLUtils::handleErrors();
    }
    return bignum;
}

inline BNImpl::bn_ctx_unique_ptr BNImpl::newBnCtx() {
    BNImpl::bn_ctx_unique_ptr ctx(BN_CTX_new(), BN_CTX_free);
    return ctx;
}

} // ecc
} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_BNIMPL_HPP_