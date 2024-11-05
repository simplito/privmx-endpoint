/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <openssl/evp.h>

#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/ecc/Point.hpp>
#include <privmx/crypto/OpenSSLUtils.hpp>
#include <privmx/crypto/openssl/ecc/PointImpl.hpp>
#include <privmx/crypto/openssl/ecc/BNImpl.hpp>
#include <privmx/crypto/CryptoConfig.hpp>

using namespace privmx::crypto::opensslimpl;
using namespace std;

#ifdef PRIVMX_DEFAULT_CRYPTO_OPENSSL
privmx::crypto::PointImpl::Ptr privmx::crypto::PointImpl::fromBuffer(const string& data) {
    return privmx::crypto::opensslimpl::PointImpl::fromBuffer(data);
}

privmx::crypto::PointImpl::Ptr privmx::crypto::PointImpl::getDefault() {
    return privmx::crypto::opensslimpl::PointImpl::getDefault();
}
#endif

PointImpl::Ptr PointImpl::fromBuffer(const string& data) {
    ec_point_unique_ptr point = oct2point(data);
    return new PointImpl(move(point));
}

PointImpl::Ptr PointImpl::getDefault() {
    return new PointImpl();
}

PointImpl::PointImpl(const PointImpl& obj) : _point(copyEcPoint(obj._point)) {}

PointImpl::PointImpl(PointImpl&& obj) : _point(move(obj._point)) {}

PointImpl::PointImpl(ec_point_unique_ptr&& point) : _point(move(point)) {}

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
    const EC_POINT* raw = _point.get();
    ec_group_unique_ptr group = getEcGroup();
    point_conversion_form_t form = compact ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;
    size_t size = EC_POINT_point2oct(group.get(), raw, form, NULL, 0, NULL);
    if (size == 0) {
        OpenSSLUtils::handleErrors();
    }
    string result(size, 0);
    unsigned char* buf = reinterpret_cast<unsigned char*>(result.data());
    if (EC_POINT_point2oct(group.get(), raw, form, buf, size, NULL) == 0) {
        OpenSSLUtils::handleErrors();
    }
    return result;
}

PointImpl::Ptr PointImpl::mul(const BNImpl::Ptr bn) const {
    validate();
    ec_group_unique_ptr group = getEcGroup();
    bn_ctx_unique_ptr ctx = newBnCtx();
    ec_point_unique_ptr result = newEcPoint();
    EC_POINT* raw_result = result.get();
    const BIGNUM* raw_bn = bn.cast<BNImpl>()->getRaw();
    const EC_POINT* raw_point = _point.get();
    BN_CTX* raw_ctx = ctx.get();
    if (EC_POINT_mul(group.get(), raw_result, NULL, raw_point, raw_bn, raw_ctx) == 0) {
        OpenSSLUtils::handleErrors();
    }
    return new PointImpl(move(result));
}

PointImpl::Ptr PointImpl::add(const PointImpl::Ptr point) const {
    validate();
    ec_group_unique_ptr group = getEcGroup();
    bn_ctx_unique_ptr ctx = newBnCtx();
    ec_point_unique_ptr result = newEcPoint();
    EC_POINT* raw_result = result.get();
    const EC_POINT* raw_point_a = _point.get();
    const EC_POINT* raw_point_b = point.cast<PointImpl>()->getRaw();
    BN_CTX* raw_ctx = ctx.get();
    if (EC_POINT_add(group.get(), raw_result, raw_point_a, raw_point_b, raw_ctx) == 0) {
        OpenSSLUtils::handleErrors();
    }
    return new PointImpl(move(result));
}

const EC_POINT* PointImpl::getRaw() const {
    validate();
    return _point.get();
}

PointImpl::ec_point_unique_ptr PointImpl::oct2point(const string& oct) {
    const unsigned char* s = reinterpret_cast<const unsigned char*>(oct.data());
    int len = oct.size();
    ec_point_unique_ptr point = newEcPoint();
    ec_group_unique_ptr group = getEcGroup();
    bn_ctx_unique_ptr ctx = newBnCtx();
    EC_POINT* raw_point = point.get();
    BN_CTX* raw_ctx = ctx.get();
    if (EC_POINT_oct2point(group.get(), raw_point, s, len, raw_ctx) == 0) {
        OpenSSLUtils::handleErrors();
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
        OpenSSLUtils::handleErrors();
    }
    return new_point;
}

PointImpl::ec_point_unique_ptr PointImpl::newEcPoint() {
    ec_group_unique_ptr group = getEcGroup();
    ec_point_unique_ptr point(EC_POINT_new(group.get()), EC_POINT_free);
    if (point.get() == NULL) {
        OpenSSLUtils::handleErrors();
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
        OpenSSLUtils::handleErrors();
    }
    return ctx;
}

void PointImpl::validate() const {
    if (!_point) {
        EmptyPointException();
    }
}
