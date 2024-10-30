#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/ecc/BN.hpp>
#include <privmx/crypto/OpenSSLUtils.hpp>
#include <privmx/crypto/driver/ecc/BNImpl.hpp>
#include <privmx/crypto/CryptoConfig.hpp>

using namespace privmx::crypto::driverimpl;
using namespace std;

#ifdef PRIVMX_DEFAULT_CRYPTO_DRIVER
privmx::crypto::BNImpl::Ptr privmx::crypto::BNImpl::fromBuffer(const string& data) {
    return privmx::crypto::driverimpl::BNImpl::fromBuffer(data);
}

privmx::crypto::BNImpl::Ptr privmx::crypto::BNImpl::getDefault() {
    return privmx::crypto::driverimpl::BNImpl::getDefault();
}
#endif

BNImpl::Ptr BNImpl::fromBuffer(const string& data) {
    bn_unique_ptr bn = bin2bignum(data);
    return new BNImpl(move(bn));
}

BNImpl::Ptr BNImpl::getDefault() {
    return new BNImpl();
}

BNImpl::BNImpl(const BNImpl& obj) : _bn(copyBignum(obj._bn)) {}

BNImpl::BNImpl(BNImpl&& obj) : _bn(move(obj._bn)) {}

BNImpl::BNImpl(bn_unique_ptr&& bn) : _bn(move(bn)) {}

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
    char* buf;
    int size;
    int status = privmxDrvEcc_bnBn2bin(_bn.get(), &buf, &size);
    if (status != 0) {
        throw PrivmxDriverEccException("bnBn2bin: " + to_string(status));
    }
    string result(buf, size);
    privmxDrvEcc_freeMem(buf);
    return result;
}

std::size_t BNImpl::getBitsLength() const {
    validate();
    int num;
    int status = privmxDrvEcc_bnBitsLength(_bn.get(), &num);
    if (status != 0) {
        throw PrivmxDriverEccException("bnGetBitsLength: " + to_string(status));
    }
    return num;
}

BNImpl::Ptr BNImpl::umod(const BNImpl::Ptr bn) const {
    validate();
    privmxDrvEcc_BN* raw;
    int status = privmxDrvEcc_bnUmod(_bn.get(), bn.cast<BNImpl>()->_bn.get(), &raw);
    if (status != 0) {
        throw PrivmxDriverEccException("bnUmod: " + to_string(status));
    }
    bn_unique_ptr res(raw, privmxDrvEcc_bnFree);
    return new BNImpl(move(res));
}

bool BNImpl::eq(const BNImpl::Ptr bn) const {
    validate();
    int res;
    int status = privmxDrvEcc_bnEq(_bn.get(), bn.cast<BNImpl>()->_bn.get(), &res);
    if (status != 0) {
        throw PrivmxDriverEccException("bnEq: " + to_string(status));
    }
    return res;
}

const privmxDrvEcc_BN* BNImpl::getRaw() const {
    validate();
    return _bn.get();
}

BNImpl::bn_unique_ptr BNImpl::bin2bignum(const string& bin) {
    privmxDrvEcc_BN* _bn;
    int status = privmxDrvEcc_bnBin2bn(bin.data(), bin.size(), &_bn);
    if (status != 0) {
        throw PrivmxDriverEccException("bnBin2bn: " + to_string(status));
    }
    return bn_unique_ptr(_bn, privmxDrvEcc_bnFree);
}

BNImpl::bn_unique_ptr BNImpl::copyBignum(const bn_unique_ptr& bn) {
    if (!bn) {
        return nullptr;
    }
    privmxDrvEcc_BN* copy;
    int status = privmxDrvEcc_bnCopy(bn.get(), &copy);
    if (status != 0) {
        throw PrivmxDriverEccException("bnCopyBn: " + to_string(status));
    }
    return bn_unique_ptr(copy, privmxDrvEcc_bnFree);
}

void BNImpl::validate() const {
    if (!_bn) {
        throw EmptyBNException();
    }
}
