#ifndef _PRIVMXLIB_CRYPTO_OPENSSL_BNIMPl_HPP_
#define _PRIVMXLIB_CRYPTO_OPENSSL_BNIMPl_HPP_

#include <functional>
#include <memory>
#include <string>
#include <openssl/bn.h>
#include <Poco/SharedPtr.h>

#include <privmx/crypto/ecc/BNImpl.hpp>

namespace privmx {
namespace crypto {
namespace opensslimpl {

class BNImpl : public privmx::crypto::BNImpl
{
public:
    using bignum_unique_ptr = std::unique_ptr<BIGNUM, std::function<decltype(BN_free)>>;

    static BNImpl::Ptr fromBuffer(const std::string& data);
    static BNImpl::Ptr getDefault();
    BNImpl() = default;
    BNImpl(const BNImpl& obj);
    BNImpl(BNImpl&& obj);
    BNImpl(bignum_unique_ptr&& bn);
    BNImpl& operator=(const BNImpl& obj);
    BNImpl& operator=(BNImpl&& obj);
    operator bool() const override;
    bool isEmpty() const override;
    std::string toBuffer() const override;
    std::size_t getBitsLength() const override;
    privmx::crypto::BNImpl::Ptr umod(const privmx::crypto::BNImpl::Ptr bn) const override;
    bool eq(const privmx::crypto::BNImpl::Ptr bn) const override;
    const BIGNUM* getRaw() const;

private:
    using bn_ctx_unique_ptr = std::unique_ptr<BN_CTX, std::function<decltype(BN_CTX_free)>>;

    static bignum_unique_ptr bin2bignum(const std::string& bin);
    static bignum_unique_ptr copyBignum(const bignum_unique_ptr& bn);
    static bignum_unique_ptr newBignum();
    static bn_ctx_unique_ptr newBnCtx();
    void validate() const;

    bignum_unique_ptr _bn;
};

inline BNImpl::operator bool() const {
    return !isEmpty();
}

inline bool BNImpl::isEmpty() const {
    return !_bn;
}

} // opensslimpl
} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_OPENSSL_BNIMPl_HPP_
