/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_DRIVER_BNIMPl_HPP_
#define _PRIVMXLIB_CRYPTO_DRIVER_BNIMPl_HPP_

#include <functional>
#include <memory>
#include <string>
#include <Poco/SharedPtr.h>

#include <privmx/drv/ecc.h>

#include <privmx/crypto/ecc/BNImpl.hpp>

namespace privmx {
namespace crypto {
namespace driverimpl {

class BNImpl : public privmx::crypto::BNImpl
{
public:
    using bn_unique_ptr = std::unique_ptr<privmxDrvEcc_BN, std::function<decltype(privmxDrvEcc_bnFree)>>;

    static BNImpl::Ptr fromBuffer(const std::string& data);
    static BNImpl::Ptr getDefault();
    BNImpl() = default;
    BNImpl(const BNImpl& obj);
    BNImpl(BNImpl&& obj);
    BNImpl(bn_unique_ptr&& bn);
    BNImpl& operator=(const BNImpl& obj);
    BNImpl& operator=(BNImpl&& obj);
    operator bool() const override;
    bool isEmpty() const override;
    std::string toBuffer() const override;
    std::size_t getBitsLength() const override;
    privmx::crypto::BNImpl::Ptr umod(const privmx::crypto::BNImpl::Ptr bn) const override;
    bool eq(const privmx::crypto::BNImpl::Ptr bn) const override;
    const privmxDrvEcc_BN* getRaw() const;

private:
    static bn_unique_ptr bin2bignum(const std::string& bin);
    static bn_unique_ptr copyBignum(const bn_unique_ptr& bn);
    void validate() const;

    bn_unique_ptr _bn;
};

inline BNImpl::operator bool() const {
    return !isEmpty();
}

inline bool BNImpl::isEmpty() const {
    return !_bn;
}

} // driverimpl
} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_DRIVER_BNIMPl_HPP_
