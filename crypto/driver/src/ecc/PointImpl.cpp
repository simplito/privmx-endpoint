#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/ecc/Point.hpp>
#include <privmx/crypto/OpenSSLUtils.hpp>
#include <privmx/crypto/driver/ecc/PointImpl.hpp>
#include <privmx/crypto/driver/ecc/BNImpl.hpp>
#include <privmx/crypto/CryptoConfig.hpp>

using namespace privmx::crypto::driverimpl;
using namespace std;

#ifdef PRIVMX_DEFAULT_CRYPTO_DRIVER
privmx::crypto::PointImpl::Ptr privmx::crypto::PointImpl::fromBuffer(const string& data) {
    return privmx::crypto::driverimpl::PointImpl::fromBuffer(data);
}

privmx::crypto::PointImpl::Ptr privmx::crypto::PointImpl::getDefault() {
    return privmx::crypto::driverimpl::PointImpl::getDefault();
}
#endif

PointImpl::Ptr PointImpl::fromBuffer(const string& data) {
    point_unique_ptr point = oct2point(data);
    return new PointImpl(move(point));
}

PointImpl::Ptr PointImpl::getDefault() {
    return new PointImpl();
}

PointImpl::PointImpl(const PointImpl& obj) : _point(copyEcPoint(obj._point)) {}

PointImpl::PointImpl(PointImpl&& obj) : _point(move(obj._point)) {}

PointImpl::PointImpl(point_unique_ptr&& point) : _point(move(point)) {}

PointImpl& PointImpl::operator=(const PointImpl& obj) {
    _point = copyEcPoint(obj._point);
    return *this;
}

PointImpl& PointImpl::operator=(PointImpl&& obj) {
    _point = move(obj._point);
    return *this;
}

string PointImpl::encode(bool compact) const {
    validate();
    char* buf;
    int size;
    int status = privmxDrvEcc_pointEncode(_point.get(), compact, &buf, &size);
    if (status != 0) {
        throw PrivmxDriverEccException("pointEncode: " + to_string(status));
    }
    string res(buf, size);
    privmxDrvEcc_freeMem(buf);
    return res;
}

PointImpl::Ptr PointImpl::mul(const BNImpl::Ptr bn) const {
    validate();
    privmxDrvEcc_Point* point;
    int status = privmxDrvEcc_pointMul(_point.get(), bn.cast<BNImpl>()->getRaw(), &point);
    if (status != 0) {
        throw PrivmxDriverEccException("pointMul: " + to_string(status));
    }
    point_unique_ptr ptr(point, privmxDrvEcc_pointFree);
    return new PointImpl(move(ptr));
}

PointImpl::Ptr PointImpl::add(const PointImpl::Ptr point) const {
    validate();
    privmxDrvEcc_Point* res;
    int status = privmxDrvEcc_pointAdd(_point.get(), point.cast<PointImpl>()->_point.get(), &res);
    if (status != 0) {
        throw PrivmxDriverEccException("pointAdd: " + to_string(status));
    }
    point_unique_ptr ptr(res, privmxDrvEcc_pointFree);
    return new PointImpl(move(ptr));
}

const privmxDrvEcc_Point* PointImpl::getRaw() const {
    validate();
    return _point.get();
}

PointImpl::point_unique_ptr PointImpl::oct2point(const string& oct) {
    privmxDrvEcc_Point* res;
    int status = privmxDrvEcc_pointOct2point(oct.data(), oct.size(), &res);
    if (status != 0) {
        throw PrivmxDriverEccException("pointAdd: " + to_string(status));
    }
    return point_unique_ptr(res, privmxDrvEcc_pointFree);
}

PointImpl::point_unique_ptr PointImpl::copyEcPoint(const point_unique_ptr& point) {
    if (!point) {
        return nullptr;
    }
    privmxDrvEcc_Point* res;
    int status = privmxDrvEcc_pointCopy(point.get(), &res);
    if (status != 0) {
        throw PrivmxDriverEccException("pointAdd: " + to_string(status));
    }
    return point_unique_ptr(res, privmxDrvEcc_pointFree);
}

void PointImpl::validate() const {
    if (!_point) {
        throw EmptyPointException();
    }
}
