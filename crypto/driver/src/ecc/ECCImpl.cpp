#include <privmx/crypto/ecc/ECC.hpp>
#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/OpenSSLUtils.hpp>
#include <privmx/crypto/driver/ecc/ECCImpl.hpp>
#include <privmx/crypto/CryptoConfig.hpp>

using namespace privmx;
using namespace privmx::crypto::driverimpl;
using namespace std;

#ifdef PRIVMX_DEFAULT_CRYPTO_DRIVER
privmx::crypto::ECCImpl::Ptr privmx::crypto::ECCImpl::genPair() {
    return privmx::crypto::driverimpl::ECCImpl::genPair();
}

privmx::crypto::ECCImpl::Ptr privmx::crypto::ECCImpl::fromPublicKey(const string& public_key) {
    return privmx::crypto::driverimpl::ECCImpl::fromPublicKey(public_key);
}

privmx::crypto::ECCImpl::Ptr privmx::crypto::ECCImpl::fromPrivateKey(const std::string& private_key) {
    return privmx::crypto::driverimpl::ECCImpl::fromPrivateKey(private_key);
}
#endif

ECCImpl::Ptr ECCImpl::genPair() {
    privmxDrvEcc_ECC* ecc;
    int status = privmxDrvEcc_eccGenPair(&ecc);
    if (status != 0) {
        throw PrivmxDriverEccException("eccGenPair: " + to_string(status));
    }
    ec_key_unique_ptr ptr(ecc, privmxDrvEcc_eccFree);
    return new ECCImpl(move(ptr), true);
}

ECCImpl::Ptr ECCImpl::fromPublicKey(const string& public_key) {
    privmxDrvEcc_ECC* ecc;
    int status = privmxDrvEcc_eccFromPublicKey(public_key.data(), public_key.size(), &ecc);
    if (status != 0) {
        throw PrivmxDriverEccException("eccFromPublicKey: " + to_string(status));
    }
    ec_key_unique_ptr ptr(ecc, privmxDrvEcc_eccFree);
    return new ECCImpl(move(ptr), false);
}

ECCImpl::Ptr ECCImpl::fromPrivateKey(const std::string& private_key) {
    privmxDrvEcc_ECC* ecc;
    int status = privmxDrvEcc_eccFromPrivateKey(private_key.data(), private_key.size(), &ecc);
    if (status != 0) {
        throw PrivmxDriverEccException("eccFromPrivateKey: " + to_string(status));
    }
    ec_key_unique_ptr ptr(ecc, privmxDrvEcc_eccFree);
    return new ECCImpl(move(ptr), true);
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
    PointImpl::Ptr pub = getPublicKey2();
    return pub->encode(compact);
}

PointImpl::Ptr ECCImpl::getPublicKey2() const {
    validate();
    privmxDrvEcc_Point* point;
    int status = privmxDrvEcc_eccGetPublicKey(_key.get(), &point);
    if (status != 0) {
        throw PrivmxDriverEccException("eccGetPublicKey: " + to_string(status));
    }
    PointImpl::point_unique_ptr ptr(point, privmxDrvEcc_pointFree);
    return new PointImpl(move(ptr));
}

string ECCImpl::getPrivateKey() const {
    BNImpl::Ptr bn = getPrivateKey2();
    return bn->toBuffer();
}

BNImpl::Ptr ECCImpl::getPrivateKey2() const {
    validate();
    if (!hasPrivate()) {
        return new BNImpl();
    }
    privmxDrvEcc_BN* bn;
    int status = privmxDrvEcc_eccGetPrivateKey(_key.get(), &bn);
    if (status != 0) {
        throw PrivmxDriverEccException("eccGetPrivateKey: " + to_string(status));
    }
    BNImpl::bn_unique_ptr ptr(bn, privmxDrvEcc_bnFree);
    return new BNImpl(move(ptr));
}

string ECCImpl::sign(const string& data) const {
    Signature sig = sign2(data);
    string r = sig.r->toBuffer();
    string s = sig.s->toBuffer();
    return string(1, 27)
        .append(32 - r.size(), 0).append(r)
        .append(32 - s.size(), 0).append(s);
}

ECCImpl::Signature ECCImpl::sign2(const string& data) const {
    validate();
    privmxDrvEcc_Signature sig;
    int status = privmxDrvEcc_eccSign(_key.get(), data.data(), data.size(), &sig);
    if (status != 0) {
        throw PrivmxDriverEccException("eccSign: " + to_string(status));
    }
    BNImpl::bn_unique_ptr r((privmxDrvEcc_BN*)sig.r, privmxDrvEcc_bnFree);
    BNImpl::bn_unique_ptr s((privmxDrvEcc_BN*)sig.s, privmxDrvEcc_bnFree);
    Signature signature{new BNImpl(move(r)), new BNImpl(move(s))};
    return signature;
}

bool ECCImpl::verify(const std::string& data, const std::string& signature) const {
    ECCImpl::Signature sig;
    sig.r = BNImpl::fromBuffer(signature.substr(1, 32));
    sig.s = BNImpl::fromBuffer(signature.substr(33, 32));
    return verify2(data, sig);
}

bool ECCImpl::verify2(const std::string& data, const ECCImpl::Signature& signature) const {
    validate();
    privmxDrvEcc_Signature sig;
    sig.r = signature.r.cast<BNImpl>()->getRaw();
    sig.s = signature.s.cast<BNImpl>()->getRaw();
    int res;
    int status = privmxDrvEcc_eccVerify(_key.get(), data.data(), data.size(), &sig, &res);
    if (status != 0) {
        throw PrivmxDriverEccException("eccVerify: " + to_string(status));
    }
    return res;
}

string ECCImpl::derive(const ECCImpl::Ptr ecc) const {
    validate();
    char* buf;
    int size;
    int status = privmxDrvEcc_eccDerive(_key.get(), ecc.cast<ECCImpl>()->_key.get(), &buf, &size);
    if (status != 0) {
        throw PrivmxDriverEccException("eccDerive: " + to_string(status));
    }
    string secret(buf, size);
    privmxDrvEcc_freeMem(buf);
    return secret;
}

string ECCImpl::getOrder() const {
    BNImpl::Ptr bn = getOrder2();
    return bn->toBuffer();
}

BNImpl::Ptr ECCImpl::getOrder2() const {
    privmxDrvEcc_BN* bn;
    int status = privmxDrvEcc_eccGetOrder(&bn);
    if (status != 0) {
        throw PrivmxDriverEccException("eccGetOrder: " + to_string(status));
    }
    BNImpl::bn_unique_ptr ptr(bn, privmxDrvEcc_bnFree);
    return new BNImpl(move(ptr));
}

PointImpl::Ptr ECCImpl::getGenerator() const {
    privmxDrvEcc_Point* point;
    int status = privmxDrvEcc_eccGetGenerator(&point);
    if (status != 0) {
        throw PrivmxDriverEccException("eccGetGenerator: " + to_string(status));
    }
    PointImpl::point_unique_ptr ptr(point, privmxDrvEcc_pointFree);
    return new PointImpl(move(ptr));
}

BNImpl::Ptr ECCImpl::getEcOrder() const {
    privmxDrvEcc_BN* bn;
    int status = privmxDrvEcc_eccGetOrder(&bn);
    if (status != 0) {
        throw PrivmxDriverEccException("eccGetOrder: " + to_string(status));
    }
    BNImpl::bn_unique_ptr ptr(bn, privmxDrvEcc_bnFree);
    return new BNImpl(move(ptr));
}

PointImpl::Ptr ECCImpl::getEcGenerator() const {
    privmxDrvEcc_Point* point;
    int status = privmxDrvEcc_eccGetGenerator(&point);
    if (status != 0) {
        throw PrivmxDriverEccException("eccGetGenerator: " + to_string(status));
    }
    PointImpl::point_unique_ptr ptr(point, privmxDrvEcc_pointFree);
    return new PointImpl(move(ptr));
}

ECCImpl::ec_key_unique_ptr ECCImpl::copyEcKey(const ec_key_unique_ptr& key) {
    if (!key) {
        return nullptr;
    }
    privmxDrvEcc_ECC* ecc;
    int status = privmxDrvEcc_eccCopy(key.get(), &ecc);
    if (status != 0) {
        throw PrivmxDriverEccException("eccCopyEcc: " + to_string(status));
    }
    return ec_key_unique_ptr(ecc, privmxDrvEcc_eccFree);
}

void ECCImpl::validate() const {
    if (!_key) {
        throw ECCIsNotInitializedException();
    }
}
