#ifndef _PRIVMXLIB_CRYPTO_BNIMPL_HPP_
#define _PRIVMXLIB_CRYPTO_BNIMPL_HPP_

#include <string>
#include <Poco/SharedPtr.h>

namespace privmx {
namespace crypto {

class BNImpl
{
public:
    using Ptr = Poco::SharedPtr<BNImpl>;

    static BNImpl::Ptr fromBuffer(const std::string& data);
    static BNImpl::Ptr getDefault();
    virtual ~BNImpl() = default;
    virtual operator bool() const = 0;
    virtual bool isEmpty() const = 0;
    virtual std::string toBuffer() const = 0;
    virtual std::size_t getBitsLength() const = 0;
    virtual BNImpl::Ptr umod(const BNImpl::Ptr bn) const = 0;
    virtual bool eq(const BNImpl::Ptr bn) const = 0;
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_BNIMPL_HPP_
