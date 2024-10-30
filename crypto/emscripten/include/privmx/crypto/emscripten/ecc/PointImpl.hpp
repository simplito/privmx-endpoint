#ifndef _PRIVMXLIB_CRYPTO_EMSCRIPTEN_POINTIMPL_HPP_
#define _PRIVMXLIB_CRYPTO_EMSCRIPTEN_POINTIMPL_HPP_

#include <string>
#include <Poco/SharedPtr.h>

#include <privmx/crypto/ecc/BN.hpp>
#include <privmx/crypto/ecc/PointImpl.hpp>

namespace privmx {
namespace crypto {
namespace emscriptenimpl {

class PointImpl : public privmx::crypto::PointImpl
{
public:
    static PointImpl::Ptr fromBuffer(const std::string& data);
    static PointImpl::Ptr getDefault();
    PointImpl() = default;
    PointImpl(const PointImpl& obj);
    PointImpl(PointImpl&& obj);
    PointImpl(const std::string& point);
    PointImpl& operator=(const PointImpl& obj);
    PointImpl& operator=(PointImpl&& obj);
    operator bool() const override;
    bool isEmpty() const override;
    std::string encode(bool compact = false) const override;
    privmx::crypto::PointImpl::Ptr mul(const privmx::crypto::BNImpl::Ptr bn) const override;
    privmx::crypto::PointImpl::Ptr add(const privmx::crypto::PointImpl::Ptr point) const override;

private:
    void validate() const;

    std::string _point;
};

inline PointImpl::operator bool() const {
    return !isEmpty();
}

inline bool PointImpl::isEmpty() const {
    return _point.empty();
}

} // emscriptenimpl
} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_EMSCRIPTEN_POINTIMPL_HPP_
