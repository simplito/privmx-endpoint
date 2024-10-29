#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <privmx/crypto/ecc/ECC.hpp>
#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/OpenSSLUtils.hpp>
#include <privmx/crypto/openssl/ecc/ECCImpl.hpp>
#include <privmx/crypto/CryptoConfig.hpp>

using namespace privmx;
using namespace privmx::crypto::opensslimpl;
using namespace std;

#ifdef PRIVMX_DEFAULT_CRYPTO_OPENSSL
privmx::crypto::ECCImpl::Ptr privmx::crypto::ECCImpl::genPair() {
    return privmx::crypto::opensslimpl::ECCImpl::genPair();
}

privmx::crypto::ECCImpl::Ptr privmx::crypto::ECCImpl::fromPublicKey(const string& public_key) {
    return privmx::crypto::opensslimpl::ECCImpl::fromPublicKey(public_key);
}

privmx::crypto::ECCImpl::Ptr privmx::crypto::ECCImpl::fromPrivateKey(const std::string& private_key) {
    return privmx::crypto::opensslimpl::ECCImpl::fromPrivateKey(private_key);
}
#endif

ECCImpl::Ptr ECCImpl::genPair() {
    ec_key_unique_ptr key = newEcKey();
    EC_KEY* raw_key = key.get();
    if (EC_KEY_generate_key(raw_key) == 0) {
        OpenSSLUtils::handleErrors();
    }
    return new ECCImpl(move(key), true);
}

ECCImpl::Ptr ECCImpl::fromPublicKey(const string& public_key) {
    ec_key_unique_ptr key = newEcKey();
    ec_point_unique_ptr public_point = oct2point(key, public_key);
    setPublicKey(key, public_point);
    checkKey(key);
    return new ECCImpl(move(key), false);
}

ECCImpl::Ptr ECCImpl::fromPrivateKey(const std::string& private_key) {
    ec_key_unique_ptr key = newEcKey();
    bignum_unique_ptr private_bn = bin2bignum(private_key);
    setPrivateKey(key, private_bn);
    ec_point_unique_ptr public_point = mul(key);
    setPublicKey(key, public_point);
    checkKey(key);
    return new ECCImpl(move(key), true);
}

ECCImpl::ECCImpl() : _key(nullptr) {}

ECCImpl::ECCImpl(const ECCImpl& obj) : _key(copyEcKey(obj._key)), _has_priv(obj._has_priv) {}

ECCImpl::ECCImpl(ECCImpl&& obj) : _key(move(obj._key)), _has_priv(move(obj._has_priv)) {}

ECCImpl::ECCImpl(ec_key_unique_ptr&& key, bool has_priv) : _key(move(key)), _has_priv(has_priv) {}

ECCImpl& ECCImpl::operator=(const ECCImpl& obj) {
    _key = copyEcKey(obj._key);
    _has_priv = obj._has_priv;
    return *this;
}

ECCImpl& ECCImpl::operator=(ECCImpl&& obj) {
    _key = move(obj._key);
    _has_priv = move(obj._has_priv);
    return *this;
}

string ECCImpl::getPublicKey(bool compact) const {
    const EC_KEY* raw_key = checkIfInitializedKeyAndGet();
    const EC_POINT* public_point = EC_KEY_get0_public_key(raw_key);
    const EC_GROUP* group = EC_KEY_get0_group(raw_key);
    point_conversion_form_t form = compact ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;
    size_t size = EC_POINT_point2oct(group, public_point, form, NULL, 0, NULL);
    if (size == 0) {
        OpenSSLUtils::handleErrors();
    }
    string public_key(size, 0);
    unsigned char* buf = reinterpret_cast<unsigned char*>(public_key.data());
    if (EC_POINT_point2oct(group, public_point, form, buf, size, NULL) == 0) {
        OpenSSLUtils::handleErrors();
    }
    return public_key;
}

PointImpl::Ptr ECCImpl::getPublicKey2() const {
    const EC_KEY* raw_key = checkIfInitializedKeyAndGet();
    const EC_POINT* public_point = EC_KEY_get0_public_key(raw_key);
    const EC_GROUP* group = EC_KEY_get0_group(raw_key);
    return new PointImpl(copyEcPoint(public_point, group));
}

string ECCImpl::getPrivateKey() const {
    const EC_KEY* raw_key = checkIfInitializedKeyAndGet();
    const BIGNUM* priv = EC_KEY_get0_private_key(raw_key);
    size_t size = BN_num_bytes(priv);
    string private_key(size, 0);
    unsigned char* to = reinterpret_cast<unsigned char*>(private_key.data());
    BN_bn2bin(priv, to);
    return private_key;
}

BNImpl::Ptr ECCImpl::getPrivateKey2() const {
    if (!hasPrivate()) {
        return new BNImpl();
    }
    const EC_KEY* raw_key = checkIfInitializedKeyAndGet();
    const BIGNUM* priv = EC_KEY_get0_private_key(raw_key);
    return new BNImpl(copyBignum(priv));
}

string ECCImpl::sign(const string& data) const {
    EC_KEY* raw_key = checkIfInitializedKeyAndGet();
    const unsigned char* dgst = reinterpret_cast<const unsigned char*>(data.data());
    int dgst_len = data.size();
    ecdsa_sig_unique_ptr sig(ECDSA_do_sign(dgst, dgst_len, raw_key), ECDSA_SIG_free);
    const ECDSA_SIG* raw_sig = sig.get();
    if (raw_sig == NULL) {
        OpenSSLUtils::handleErrors();
    }
    string result(65, 0);
    unsigned char* buf = reinterpret_cast<unsigned char*>(result.data());
    result[0] = 27;
    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(raw_sig, &r, &s);
    BN_bn2bin(r, &buf[1 + 32 - BN_num_bytes(r)]);
    BN_bn2bin(s, &buf[33 + 32 - BN_num_bytes(s)]);
    return result;
}

ECCImpl::Signature ECCImpl::sign2(const string& data) const {
    EC_KEY* raw_key = checkIfInitializedKeyAndGet();
    const unsigned char* dgst = reinterpret_cast<const unsigned char*>(data.data());
    int dgst_len = data.size();
    ecdsa_sig_unique_ptr sig(ECDSA_do_sign(dgst, dgst_len, raw_key), ECDSA_SIG_free);
    const ECDSA_SIG* raw_sig = sig.get();
    if (raw_sig == NULL) {
        OpenSSLUtils::handleErrors();
    }
    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(raw_sig, &r, &s);
    Signature signature{new BNImpl(copyBignum(r)), new BNImpl(copyBignum(s))};
    return signature;
}

bool ECCImpl::verify(const std::string& data, const std::string& signature) const {
    EC_KEY* raw_key = checkIfInitializedKeyAndGet();
    if (signature.size() != 65) {
        throw InvalidSignatureSizeException();
    }
    if (signature.front() < 27 || signature.front() > 42) {
        throw InvalidSignatureHeaderException();
    }
    const unsigned char* dgst = reinterpret_cast<const unsigned char*>(data.data());
    int dgst_len = data.size();
    const unsigned char* sign = reinterpret_cast<const unsigned char*>(signature.data());
    ecdsa_sig_unique_ptr sig(ECDSA_SIG_new(), ECDSA_SIG_free);
    ECDSA_SIG* raw_sig = sig.get();
    if (raw_sig == NULL) {
        OpenSSLUtils::handleErrors();
    }
    bignum_unique_ptr r = newBignum();
    bignum_unique_ptr s = newBignum();
    BIGNUM* raw_r = r.get();
    BIGNUM* raw_s = s.get();
    if (BN_bin2bn(&sign[1], 32, raw_r) == NULL) {
        OpenSSLUtils::handleErrors();
    }
    if (BN_bin2bn(&sign[33], 32, raw_s) == NULL) {
        OpenSSLUtils::handleErrors();
    }
    if (ECDSA_SIG_set0(raw_sig, raw_r, raw_s) == 0) {
        OpenSSLUtils::handleErrors();
    }
    // Release r and s, cause calling ECDSA_SIG_set0() transfers
    // the memory management of the values to the ECDSA_SIG object
    r.release();
    s.release();
    int result = ECDSA_do_verify(dgst, dgst_len, raw_sig, raw_key);
    if (result == -1) {
        OpenSSLUtils::handleErrors();
    }
    return (result == 1);
}

bool ECCImpl::verify2(const std::string& data, const ECCImpl::Signature& signature) const {
    EC_KEY* raw_key = checkIfInitializedKeyAndGet();
    if (signature.r->getBitsLength() > 256 || signature.s->getBitsLength() > 256) {
        throw InvalidSignatureSizeException();
    }
    const unsigned char* dgst = reinterpret_cast<const unsigned char*>(data.data());
    int dgst_len = data.size();
    ecdsa_sig_unique_ptr sig(ECDSA_SIG_new(), ECDSA_SIG_free);
    ECDSA_SIG* raw_sig = sig.get();
    if (raw_sig == NULL) {
        OpenSSLUtils::handleErrors();
    }
    bignum_unique_ptr r = copyBignum(signature.r.cast<BNImpl>()->getRaw());
    bignum_unique_ptr s = copyBignum(signature.s.cast<BNImpl>()->getRaw());
    BIGNUM* raw_r = r.get();
    BIGNUM* raw_s = s.get();
    if (ECDSA_SIG_set0(raw_sig, raw_r, raw_s) == 0) {
        OpenSSLUtils::handleErrors();
    }
    // Release r and s, cause calling ECDSA_SIG_set0() transfers
    // the memory management of the values to the ECDSA_SIG object
    r.release();
    s.release();
    int result = ECDSA_do_verify(dgst, dgst_len, raw_sig, raw_key);
    if (result == -1) {
        OpenSSLUtils::handleErrors();
    }
    return (result == 1);
}

string ECCImpl::derive(const ECCImpl::Ptr ecc) const {
    const EC_KEY* raw_key = checkIfInitializedKeyAndGet();
    const EC_GROUP* group = EC_KEY_get0_group(raw_key);
    const EC_POINT* raw_point = ecc.cast<ECCImpl>()->getEcPoint();
    int field_size = EC_GROUP_get_degree(group);
    size_t secret_len = (field_size + 7) / 8;
    string secret(secret_len, 0);
    char* out = secret.data();
    if (ECDH_compute_key(out, secret_len, raw_point, raw_key, NULL) <= 0) {
        OpenSSLUtils::handleErrors();
    }
    return secret;
}

string ECCImpl::getOrder() const {
    const EC_KEY* raw_key = checkIfInitializedKeyAndGet();
    const EC_GROUP* group = EC_KEY_get0_group(raw_key);
    const BIGNUM* order_bn = EC_GROUP_get0_order(group);
    size_t size = BN_num_bytes(order_bn);
    string order(size, 0);
    unsigned char* to = reinterpret_cast<unsigned char*>(order.data());
    BN_bn2bin(order_bn, to);
    return order;
}

BNImpl::Ptr ECCImpl::getOrder2() const {
    const EC_KEY* raw_key = _key.get();
    const EC_GROUP* group = EC_KEY_get0_group(raw_key);
    const BIGNUM* order = EC_GROUP_get0_order(group);
    return new BNImpl(copyBignum(order));
}

PointImpl::Ptr ECCImpl::getGenerator() const {
    const EC_KEY* raw_key = _key.get();
    const EC_GROUP* group = EC_KEY_get0_group(raw_key);
    const EC_POINT* g = EC_GROUP_get0_generator(group);
    return new PointImpl(copyEcPoint(g, group));
}

BNImpl::Ptr ECCImpl::getEcOrder() const {
    ec_group_unique_ptr group = getEcGroup();
    const EC_GROUP* raw_group = group.get();
    const BIGNUM* order = EC_GROUP_get0_order(raw_group);
    return new BNImpl(copyBignum(order));
}

PointImpl::Ptr ECCImpl::getEcGenerator() const {
    ec_group_unique_ptr group = getEcGroup();
    const EC_GROUP* raw_group = group.get();
    const EC_POINT* g = EC_GROUP_get0_generator(raw_group);
    return new PointImpl(copyEcPoint(g, raw_group));
}

ECCImpl::ec_key_unique_ptr ECCImpl::newEcKey() {
    ec_key_unique_ptr key(EC_KEY_new_by_curve_name(NID_secp256k1), EC_KEY_free);
    if (key.get() == NULL) {
        OpenSSLUtils::handleErrors();
    }
    return key;
}

ECCImpl::ec_key_unique_ptr ECCImpl::copyEcKey(const ec_key_unique_ptr& key) {
    if (!key) {
        return nullptr;
    }
    ec_key_unique_ptr new_key = newEcKey();
    EC_KEY* dst = new_key.get();
    const EC_KEY* src = key.get();
    if (EC_KEY_copy(dst, src) == NULL) {
        OpenSSLUtils::handleErrors();
    }
    return new_key;
}

ECCImpl::bignum_unique_ptr ECCImpl::newBignum() {
    bignum_unique_ptr bignum(BN_new(), BN_free);
    if (bignum.get() == NULL) {
        OpenSSLUtils::handleErrors();
    }
    return bignum;
}

ECCImpl::bignum_unique_ptr ECCImpl::copyBignum(const BIGNUM* raw_bn) {
    if (!raw_bn) {
        return nullptr;
    }
    bignum_unique_ptr bn = newBignum();
    BIGNUM* dst = bn.get();
    if (BN_copy(dst, raw_bn) == NULL) {
        OpenSSLUtils::handleErrors();
    }
    return bn;
}

ECCImpl::bn_ctx_unique_ptr ECCImpl::newBnCtx() {
    bn_ctx_unique_ptr ctx(BN_CTX_new(), BN_CTX_free);
    if (ctx.get() == NULL) {
        OpenSSLUtils::handleErrors();
    }
    return ctx;
}

ECCImpl::ec_point_unique_ptr ECCImpl::copyEcPoint(const EC_POINT* raw_point, const EC_GROUP* group) {
    if (!raw_point) {
        return nullptr;
    }
    ec_point_unique_ptr new_point = newEcPoint(group);
    EC_POINT* dst = new_point.get();
    if (EC_POINT_copy(dst, raw_point) == 0) {
        OpenSSLUtils::handleErrors();
    }
    return new_point;
}

ECCImpl::ec_point_unique_ptr ECCImpl::newEcPoint(const EC_GROUP* group) {
    ec_point_unique_ptr point(EC_POINT_new(group), EC_POINT_free);
    if (point.get() == NULL) {
        OpenSSLUtils::handleErrors();
    }
    return point;
}

void ECCImpl::setPublicKey(const ec_key_unique_ptr& key, const ec_point_unique_ptr& public_point) {
    EC_KEY* raw_key = key.get();
    const EC_POINT* raw_public_point = public_point.get();
    if (EC_KEY_set_public_key(raw_key, raw_public_point) == 0) {
        OpenSSLUtils::handleErrors();
    }
}

void ECCImpl::setPrivateKey(const ec_key_unique_ptr& key, const bignum_unique_ptr& private_key) {
    EC_KEY* raw_key = key.get();
    const BIGNUM* raw_private_key = private_key.get();
    if (EC_KEY_set_private_key(raw_key, raw_private_key) == 0) {
        OpenSSLUtils::handleErrors();
    }
}

void ECCImpl::checkKey(const ec_key_unique_ptr& key) {
    const EC_KEY* raw_key = key.get();
    if (EC_KEY_check_key(raw_key) == 0) {
        OpenSSLUtils::handleErrors();
    }
}

ECCImpl::ec_point_unique_ptr ECCImpl::mul(ec_key_unique_ptr& key) {
    const EC_KEY* raw_key = key.get();
    const EC_GROUP* group = EC_KEY_get0_group(raw_key);
    const BIGNUM* raw_private_key = EC_KEY_get0_private_key(raw_key);
    bn_ctx_unique_ptr ctx = newBnCtx();
    BN_CTX* raw_ctx = ctx.get();
    ec_point_unique_ptr public_point = newEcPoint(group);
    EC_POINT* raw_public_point = public_point.get();
    if (EC_POINT_mul(group, raw_public_point, raw_private_key, NULL, NULL, raw_ctx) == 0) {
        OpenSSLUtils::handleErrors();
    }
    return public_point;
}

ECCImpl::bignum_unique_ptr ECCImpl::bin2bignum(const string& bin) {
    const unsigned char* s = reinterpret_cast<const unsigned char*>(bin.data());
    int len = bin.size();
    bignum_unique_ptr bignum = newBignum();
    BIGNUM* raw_bignum = bignum.get();
    if (BN_bin2bn(s, len, raw_bignum) == NULL) {
        OpenSSLUtils::handleErrors();
    }
    return bignum;
}

ECCImpl::ec_point_unique_ptr ECCImpl::oct2point(const ec_key_unique_ptr& key, const string& oct) {
    const EC_KEY* raw_key = key.get();
    const EC_GROUP* group = EC_KEY_get0_group(raw_key);
    const unsigned char* buf = reinterpret_cast<const unsigned char*>(oct.data());
    size_t len = oct.size();
    bn_ctx_unique_ptr ctx = newBnCtx();
    BN_CTX* raw_ctx = ctx.get();
    ec_point_unique_ptr public_point = newEcPoint(group);
    EC_POINT* raw_public_point = public_point.get();
    if (EC_POINT_oct2point(group, raw_public_point, buf, len, raw_ctx) == 0) {
        OpenSSLUtils::handleErrors();
    }
    return public_point;
}

ECCImpl::ec_group_unique_ptr ECCImpl::getEcGroup() {
    ec_group_unique_ptr group(EC_GROUP_new_by_curve_name(NID_secp256k1), EC_GROUP_free);
    return group;
}

EC_KEY* ECCImpl::checkIfInitializedKeyAndGet() const {
    if (!_key) {
        throw ECCIsNotInitializedException();
    }
    return _key.get();
}
