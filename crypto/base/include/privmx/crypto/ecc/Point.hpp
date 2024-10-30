#ifndef _PRIVMXLIB_CRYPTO_POINT_HPP_
#define _PRIVMXLIB_CRYPTO_POINT_HPP_

#include <string>

#include <privmx/crypto/ecc/BN.hpp>
#include <privmx/crypto/ecc/PointImpl.hpp>

namespace privmx {
namespace crypto {

class Point
{
public:
    static Point fromBuffer(const std::string& data);
    Point();
    Point(const Point& obj);
    Point(Point&& obj);
    Point(PointImpl::Ptr impl);
    Point& operator=(const Point& obj);
    Point& operator=(Point&& obj);
    operator bool() const;
    bool isEmpty() const;
    std::string encode(bool compact = false) const;
    Point mul(const BN& bn) const;
    Point add(const Point& point) const;
    PointImpl::Ptr getImpl() const;

private:    
    PointImpl::Ptr _impl;
};

inline Point Point::fromBuffer(const std::string& data) {
    return Point(PointImpl::fromBuffer(data));
}

inline Point::Point() {
    _impl = PointImpl::getDefault();
}

inline Point::Point(const Point& obj) {
    _impl = obj._impl;    
}

inline Point::Point(Point&& obj) {
    _impl = obj._impl;
}

inline Point::Point(PointImpl::Ptr impl) {
    _impl = impl;
}

inline Point& Point::operator=(const Point& obj) {
    _impl = obj._impl;
    return *this;
}

inline Point& Point::operator=(Point&& obj) {
    _impl = obj._impl;
    return *this;
}

inline Point::operator bool() const {
    return !_impl->isEmpty();
}

inline bool Point::isEmpty() const {
    return !_impl->isEmpty();
}

inline std::string Point::encode(bool compact) const {
    return _impl->encode(compact);
}

inline Point Point::mul(const BN& bn) const {
    return _impl->mul(bn.getImpl());
}

inline Point Point::add(const Point& point) const {
    return _impl->add(point._impl);
}

inline PointImpl::Ptr Point::getImpl() const {
    return _impl;
}

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_POINT_HPP_
