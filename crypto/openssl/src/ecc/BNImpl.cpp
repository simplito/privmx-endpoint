#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/ecc/BN.hpp>
#include <privmx/crypto/OpenSSLUtils.hpp>
#include <privmx/crypto/openssl/ecc/BNImpl.hpp>
#include <privmx/crypto/CryptoConfig.hpp>

using namespace privmx::crypto::opensslimpl;
using namespace std;

#ifdef PRIVMX_DEFAULT_CRYPTO_OPENSSL
privmx::crypto::BNImpl::Ptr privmx::crypto::BNImpl::fromBuffer(const string& data) {
    return privmx::crypto::opensslimpl::BNImpl::fromBuffer(data);
}

privmx::crypto::BNImpl::Ptr privmx::crypto::BNImpl::getDefault() {
    return privmx::crypto::opensslimpl::BNImpl::getDefault();
}
#endif

BNImpl::Ptr BNImpl::fromBuffer(const string& data) {
    bignum_unique_ptr bn = bin2bignum(data);
    return new BNImpl(move(bn));
}

BNImpl::Ptr BNImpl::getDefault() {
    return new BNImpl();
}

BNImpl::BNImpl(const BNImpl& obj) : _bn(copyBignum(obj._bn)) {}

BNImpl::BNImpl(BNImpl&& obj) : _bn(move(obj._bn)) {}

BNImpl::BNImpl(bignum_unique_ptr&& bn) : _bn(move(bn)) {}

BNImpl& BNImpl::operator=(const BNImpl& obj) {
    _bn = copyBignum(obj._bn);
    return *this;
}

BNImpl& BNImpl::operator=(BNImpl&& obj) {
    _bn = move(obj._bn);
    return *this;
}

string BNImpl::toBuffer() const {
    validate();
    const BIGNUM* raw = _bn.get();
    size_t size = BN_num_bytes(raw);
    string result(size, 0);
    unsigned char* to = reinterpret_cast<unsigned char*>(result.data());
    BN_bn2bin(raw, to);
    return result;
}

std::size_t BNImpl::getBitsLength() const {
    validate();
    const BIGNUM* raw = _bn.get();
    return BN_num_bits(raw);
}

BNImpl::Ptr BNImpl::umod(const BNImpl::Ptr bn) const {
    validate();
    bn_ctx_unique_ptr ctx = newBnCtx();
    bignum_unique_ptr result = newBignum();
    BIGNUM* raw_result = result.get();
    const BIGNUM* raw_bn_a = _bn.get();
    const BIGNUM* raw_bn_m = bn.cast<BNImpl>()->getRaw();
    BN_CTX* raw_ctx = ctx.get();
    if (BN_nnmod(raw_result, raw_bn_a, raw_bn_m, raw_ctx) == 0) {
        OpenSSLUtils::handleErrors();
    }
    return new BNImpl(move(result));
}

bool BNImpl::eq(const BNImpl::Ptr bn) const {
    validate();
    const BIGNUM* raw_bn_a = _bn.get();
    const BIGNUM* raw_bn_b = bn.cast<BNImpl>()->getRaw();
    return BN_cmp(raw_bn_a, raw_bn_b) == 0;
}

const BIGNUM* BNImpl::getRaw() const {
    validate();
    return _bn.get();
}

BNImpl::bignum_unique_ptr BNImpl::bin2bignum(const string& bin) {
    const unsigned char* s = reinterpret_cast<const unsigned char*>(bin.data());
    int len = bin.size();
    bignum_unique_ptr bignum = newBignum();
    BIGNUM* raw_bignum = bignum.get();
    if (BN_bin2bn(s, len, raw_bignum) == NULL) {
        OpenSSLUtils::handleErrors();
    }
    return bignum;
}

BNImpl::bignum_unique_ptr BNImpl::copyBignum(const bignum_unique_ptr& bn) {
    if (!bn) {
        return nullptr;
    }
    bignum_unique_ptr new_bn = newBignum();
    BIGNUM* dst = new_bn.get();
    const BIGNUM* src = bn.get();
    if (BN_copy(dst, src) == NULL) {
        OpenSSLUtils::handleErrors();
    }
    return new_bn;
}

BNImpl::bignum_unique_ptr BNImpl::newBignum() {
    bignum_unique_ptr bignum(BN_new(), BN_free);
    if (bignum.get() == NULL) {
        OpenSSLUtils::handleErrors();
    }
    return bignum;
}

BNImpl::bn_ctx_unique_ptr BNImpl::newBnCtx() {
    bn_ctx_unique_ptr ctx(BN_CTX_new(), BN_CTX_free);
    if (ctx.get() == NULL) {
        OpenSSLUtils::handleErrors();
    }
    return ctx;
}

void BNImpl::validate() const {
    if (!_bn) {
        throw EmptyBNException();
    }
}
