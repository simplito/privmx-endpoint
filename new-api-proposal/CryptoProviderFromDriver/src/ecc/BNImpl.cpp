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

#include "BNImpl.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

BNImpl::Ptr BNImpl::fromBuffer(const std::string& data) {
    bn_unique_ptr bn = bin2bignum(data);
    return std::make_shared<BNImpl>(std::move(bn));
}

BNImpl::Ptr BNImpl::getDefault() {
    // return new BNImpl();
    return std::make_shared<BNImpl>();
}

BNImpl::BNImpl(const BNImpl& obj) : _bn(copyBignum(obj._bn)) {}

BNImpl::BNImpl(BNImpl&& obj) : _bn(std::move(obj._bn)) {}

BNImpl::BNImpl(bn_unique_ptr&& bn) : _bn(std::move(bn)) {}

BNImpl& BNImpl::operator=(const BNImpl& obj) {
    _bn = copyBignum(obj._bn);
    return *this;
}

BNImpl& BNImpl::operator=(BNImpl&& obj) {
    _bn = move(obj._bn);
    return *this;
}

// string BNImpl::toBuffer() const {
//     validate();
//     char* buf;
//     int size;
//     int status = privmxDrvEcc_bnBn2bin(_bn.get(), &buf, &size);
//     if (status != 0) {
//         // throw PrivmxDriverEccException("bnBn2bin: " + std::to_string(status));
//         throw std::runtime_error("bnBn2bin: " + std::to_string(status));
//     }
//     string result(buf, size);
//     privmxDrvEcc_freeMem(buf);
//     return result;
// }

// std::size_t BNImpl::getBitsLength() const {
//     validate();
//     int num;
//     int status = privmxDrvEcc_bnBitsLength(_bn.get(), &num);
//     if (status != 0) {
//         throw PrivmxDriverEccException("bnGetBitsLength: " + to_string(status));
//     }
//     return num;
// }

std::string BNImpl::toBuffer() const {
    validate();
    const BIGNUM* raw = _bn.get();
    size_t size = BN_num_bytes(raw);
    std::string result(size, 0);
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
    bn_unique_ptr result = newBignum();
    BIGNUM* raw_result = result.get();
    const BIGNUM* raw_bn_a = _bn.get();
    // const BIGNUM* raw_bn_m = bn.cast<BNImpl>()->getRaw();
    const BIGNUM* raw_bn_m = bn->_bn.get();
    BN_CTX* raw_ctx = ctx.get();
    if (BN_nnmod(raw_result, raw_bn_a, raw_bn_m, raw_ctx) == 0) {
//        OpenSSLUtils::handleErrors();
         throw std::runtime_error("BNImpl::umod error");
    }
    // return new BNImpl(move(result));
    return std::make_shared<BNImpl>(move(result));
}

bool BNImpl::eq(const BNImpl::Ptr bn) const {
    validate();
    const BIGNUM* raw_bn_a = _bn.get();
    // const BIGNUM* raw_bn_b = bn.cast<BNImpl>()->getRaw();
    const BIGNUM* raw_bn_b = bn->_bn.get(); // the same type - no need to cast
    return BN_cmp(raw_bn_a, raw_bn_b) == 0;
}

const BIGNUM* BNImpl::getRaw() const {
    validate();
    return _bn.get();
}
BNImpl::bn_unique_ptr BNImpl::bin2bignum(const std::string& bin) {
    const unsigned char* s = reinterpret_cast<const unsigned char*>(bin.data());
    int len = bin.size();
    BNImpl::bn_unique_ptr bignum = newBignum();
    BIGNUM* raw_bignum = bignum.get();
    if (BN_bin2bn(s, len, raw_bignum) == NULL) {
        return bn_unique_ptr(nullptr, NULL);
    }
    return bignum;
}

// BNImpl::bn_unique_ptr BNImpl::copyBignum(const bn_unique_ptr& bn) {
//     if (!bn) {
//         return nullptr;
//     }
//     privmxDrvEcc_BN* copy;
//     int status = privmxDrvEcc_bnCopy(bn.get(), &copy);
//     if (status != 0) {
//         throw PrivmxDriverEccException("bnCopyBn: " + to_string(status));
//     }
//     return bn_unique_ptr(copy, privmxDrvEcc_bnFree);
// }

// NEED RECHECK !!!
BNImpl::bn_unique_ptr BNImpl::copyBignum(const bn_unique_ptr& bn) {
    if (!bn) {
        return nullptr;
    }
    // privmxDrvEcc_BN* copy;
    // int status = privmxDrvEcc_bnCopy(bn.get(), &copy);
    // if (status != 0) {
    //     throw PrivmxDriverEccException("bnCopyBn: " + to_string(status));
    // }
    // return bn_unique_ptr(copy, privmxDrvEcc_bnFree);
    const BIGNUM* _src = bn.get();
    bn_unique_ptr copy = newBignum();
    if (copy == NULL) {
        throw std::runtime_error("BNImpl::bnCopyBn error");
    }
    if (BN_copy(copy.get(), _src) == NULL) {
        throw std::runtime_error("BNImpl::bnCopyBn error");
    }
    return std::move(copy);
}

// BNImpl::bn_unique_ptr BNImpl::copyBignum(const BIGNUM* raw_bn) {
//     if (!raw_bn) {
//         return bignum_unique_ptr(nullptr, NULL);
//     }
//     BNImpl::bn_unique_ptr bn = newBignum();
//     BIGNUM* dst = bn.get();
//     if (BN_copy(dst, raw_bn) == NULL) {
//         // OpenSSLUtils::handleErrors();
//     }
//     return bn;
// }

void BNImpl::validate() const {
    if (!_bn) {
        // throw EmptyBNException();
        throw std::runtime_error("BNImpl::EmptyBNException");
    }
}

} // ecc
} // cryptoservice
} // privmx
