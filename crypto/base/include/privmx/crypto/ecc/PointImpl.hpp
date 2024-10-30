#ifndef _PRIVMXLIB_CRYPTO_POINTIMPL_HPP_
#define _PRIVMXLIB_CRYPTO_POINTIMPL_HPP_

#include <string>
#include <Poco/SharedPtr.h>

namespace privmx {
namespace crypto {

class PointImpl
{
public:
    using Ptr = Poco::SharedPtr<PointImpl>;

    static PointImpl::Ptr fromBuffer(const std::string& data);
    static PointImpl::Ptr getDefault();
    virtual ~PointImpl() = default;
    virtual operator bool() const = 0;
    virtual bool isEmpty() const = 0;
    virtual std::string encode(bool compact = false) const = 0;
    virtual PointImpl::Ptr mul(const BNImpl::Ptr bn) const = 0;
    virtual PointImpl::Ptr add(const PointImpl::Ptr point) const = 0;
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_POINTIMPL_HPP_
