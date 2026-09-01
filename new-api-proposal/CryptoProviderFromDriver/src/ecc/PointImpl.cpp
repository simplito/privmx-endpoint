/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <memory>
#include <string>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "BN.hpp"
#include "PointImpl.hpp"

#include "EccExceptions.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

PointImpl::Ptr PointImpl::fromBuffer(const std::string& data) {
    ec_point_unique_ptr point = oct2point(data);
    // return new PointImpl(move(point));
    return std::make_shared<PointImpl>(std::move(point));
}

PointImpl::Ptr PointImpl::fromBuffer(BytesView data) {
    ec_point_unique_ptr point = oct2point(data);
    // return new PointImpl(move(point));
    return std::make_shared<PointImpl>(std::move(point));
}

PointImpl::Ptr PointImpl::getDefault() {
    // return new PointImpl();
    return std::make_shared<PointImpl>();
}

PointImpl::PointImpl(const PointImpl& obj) : _point(copyEcPoint(obj._point)) {}

PointImpl::PointImpl(PointImpl&& obj) : _point(std::move(obj._point)) {}

PointImpl::PointImpl(ec_point_unique_ptr&& point) : _point(std::move(point)) {}

PointImpl& PointImpl::operator=(const PointImpl& obj) {
    _point = copyEcPoint(obj._point);
    return *this;
}

PointImpl& PointImpl::operator=(PointImpl&& obj) {
    _point = move(obj._point);
    return *this;
}

std::string PointImpl::encode(bool compact) const {
    validate();
    const EC_POINT* raw = _point.get();
    ec_group_unique_ptr group = getEcGroup();
    point_conversion_form_t form = compact ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;
    size_t size = EC_POINT_point2oct(group.get(), raw, form, NULL, 0, NULL);
    if (size == 0) {
        throw PrivmxCryptoserviceEccPointImplEncodeException("encode: EC_POINT_point2oct() failure");
    }
    std::string result(size, 0);
    unsigned char* buf = reinterpret_cast<unsigned char*>(result.data());
    if (EC_POINT_point2oct(group.get(), raw, form, buf, size, NULL) == 0) {
        throw PrivmxCryptoserviceEccPointImplEncodeException("encode: EC_POINT_point2oct() failure");
    }
    return result;
}

PointImpl::Ptr PointImpl::mul(const BNImpl::Ptr bn) const {
    validate();
    ec_group_unique_ptr group = getEcGroup();
    bn_ctx_unique_ptr ctx = newBnCtx();
    ec_point_unique_ptr result = newEcPoint();
    EC_POINT* raw_result = result.get();
    // const BIGNUM* raw_bn = bn.cast<BNImpl>()->getRaw();
    const BIGNUM* raw_bn = bn->getRaw();
    const EC_POINT* raw_point = _point.get();
    BN_CTX* raw_ctx = ctx.get();
    if (EC_POINT_mul(group.get(), raw_result, NULL, raw_point, raw_bn, raw_ctx) == 0) {
        throw PrivmxCryptoserviceEccPointImplMultiplicationException("mul: EC_POINT_mul() failure");
    }
    // return new PointImpl(move(result));
    return std::make_shared<PointImpl>(move(result));
}

PointImpl::Ptr PointImpl::add(const PointImpl::Ptr point) const {
    validate();
    ec_group_unique_ptr group = getEcGroup();
    bn_ctx_unique_ptr ctx = newBnCtx();
    ec_point_unique_ptr result = newEcPoint();
    EC_POINT* raw_result = result.get();
    const EC_POINT* raw_point_a = _point.get();
    // const EC_POINT* raw_point_b = point.cast<PointImpl>()->getRaw();
    const EC_POINT* raw_point_b = std::dynamic_pointer_cast<PointImpl>(point)->getRaw();
    // const EC_POINT* raw_point_b = point->getRaw();
    BN_CTX* raw_ctx = ctx.get();
    if (EC_POINT_add(group.get(), raw_result, raw_point_a, raw_point_b, raw_ctx) == 0) {
        throw PrivmxCryptoserviceEccPointImplAddException("mul: EC_POINT_mul() failure");
    }
    // return new PointImpl(move(result));
    return std::make_shared<PointImpl>(move(result));
}

const EC_POINT* PointImpl::getRaw() const {
    validate();
    return _point.get();
}

PointImpl::ec_point_unique_ptr PointImpl::oct2point(const std::string& oct) {
    const unsigned char* s = reinterpret_cast<const unsigned char*>(oct.data());
    int len = oct.size();
    ec_point_unique_ptr point = newEcPoint();
    ec_group_unique_ptr group = getEcGroup();
    bn_ctx_unique_ptr ctx = newBnCtx();
    EC_POINT* raw_point = point.get();
    BN_CTX* raw_ctx = ctx.get();
    if (EC_POINT_oct2point(group.get(), raw_point, s, len, raw_ctx) == 0) {
        throw PrivmxCryptoserviceEccPointImplOct2PointException("oct2point: EC_POINT_oct2point() failure");
    }
    return point;
}

PointImpl::ec_point_unique_ptr PointImpl::oct2point(BytesView oct) {
    const unsigned char* s = reinterpret_cast<const unsigned char*>(oct.data());
    int len = oct.size();
    ec_point_unique_ptr point = newEcPoint();
    ec_group_unique_ptr group = getEcGroup();
    bn_ctx_unique_ptr ctx = newBnCtx();
    EC_POINT* raw_point = point.get();
    BN_CTX* raw_ctx = ctx.get();
    if (EC_POINT_oct2point(group.get(), raw_point, s, len, raw_ctx) == 0) {
        throw PrivmxCryptoserviceEccPointImplOct2PointException("oct2point: EC_POINT_oct2point() failure");
    }
    return point;
}


PointImpl::ec_point_unique_ptr PointImpl::copyEcPoint(const ec_point_unique_ptr& point) {
    if (!point) {
        return nullptr;
    }
    ec_point_unique_ptr new_point = newEcPoint();
    EC_POINT* dst = new_point.get();
    const EC_POINT* src = point.get();
    if (EC_POINT_copy(dst, src) == 0) {
        throw PrivmxCryptoserviceEccPointImplCopyException("copyEcPoint: EC_POINT_copy() failure");
    }
    return new_point;
}

PointImpl::ec_point_unique_ptr PointImpl::newEcPoint() {
    ec_group_unique_ptr group = getEcGroup();
    ec_point_unique_ptr point(EC_POINT_new(group.get()), EC_POINT_free);
    if (point.get() == NULL) {
        throw PrivmxCryptoserviceEccPointImplCreateException("newEcPoint: EC_POINT_new() failure");
    }
    return point;
}

PointImpl::ec_group_unique_ptr PointImpl::getEcGroup() {
    ec_group_unique_ptr group(EC_GROUP_new_by_curve_name(NID_secp256k1), EC_GROUP_free);
    return group;
}

PointImpl::bn_ctx_unique_ptr PointImpl::newBnCtx() {
    bn_ctx_unique_ptr ctx(BN_CTX_new(), BN_CTX_free);
    if (ctx.get() == NULL) {
        throw PrivmxCryptoserviceEccPointImplCreateCtxException("newBnCtx: BN_CTX_new() failure");
    }
    return ctx;
}

void PointImpl::validate() const {
    if (!_point) {
        throw PrivmxCryptoserviceEccPointEmptyPointException();
    }
}

} // ecc
} // cryptoservice
} // privmx
