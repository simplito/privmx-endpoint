#ifndef _PRIVMXLIB_CRYPTO_DRIVER_POINTIMPL_HPP_
#define _PRIVMXLIB_CRYPTO_DRIVER_POINTIMPL_HPP_

#include <functional>
#include <memory>
#include <string>
#include <Poco/SharedPtr.h>

#include <privmx/drv/ecc.h>

#include <privmx/crypto/ecc/BN.hpp>
#include <privmx/crypto/ecc/PointImpl.hpp>

namespace privmx {
namespace crypto {
namespace driverimpl {

class PointImpl : public privmx::crypto::PointImpl
{
public:
    using point_unique_ptr = std::unique_ptr<privmxDrvEcc_Point, std::function<decltype(privmxDrvEcc_pointFree)>>;

    static PointImpl::Ptr fromBuffer(const std::string& data);
    static PointImpl::Ptr getDefault();
    PointImpl() = default;
    PointImpl(const PointImpl& obj);
    PointImpl(PointImpl&& obj);
    PointImpl(point_unique_ptr&& bn);
    PointImpl& operator=(const PointImpl& obj);
    PointImpl& operator=(PointImpl&& obj);
    operator bool() const override;
    bool isEmpty() const override;
    std::string encode(bool compact = false) const override;
    privmx::crypto::PointImpl::Ptr mul(const privmx::crypto::BNImpl::Ptr bn) const override;
    privmx::crypto::PointImpl::Ptr add(const privmx::crypto::PointImpl::Ptr point) const override;
    const privmxDrvEcc_Point* getRaw() const;

private:
    static point_unique_ptr oct2point(const std::string& oct);
    static point_unique_ptr copyEcPoint(const point_unique_ptr& point);
    void validate() const;

    point_unique_ptr _point;
};

inline PointImpl::operator bool() const {
    return !isEmpty();
}

inline bool PointImpl::isEmpty() const {
    return !_point;
}

} // driverimpl
} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_DRIVER_POINTIMPL_HPP_
