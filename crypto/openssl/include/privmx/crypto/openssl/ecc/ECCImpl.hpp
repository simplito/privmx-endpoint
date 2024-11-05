/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_OPENSSL_ECCIMPL_HPP_
#define _PRIVMXLIB_CRYPTO_OPENSSL_ECCIMPL_HPP_

#include <functional>
#include <memory>
#include <string>
#include <openssl/ec.h>
#include <Poco/SharedPtr.h>

#include <privmx/crypto/ecc/ECCImpl.hpp>
#include <privmx/crypto/openssl/ecc/BNImpl.hpp>
#include <privmx/crypto/openssl/ecc/PointImpl.hpp>

namespace privmx {
namespace crypto {
namespace opensslimpl {

class ECCImpl : public privmx::crypto::ECCImpl
{
public:
    using ec_key_unique_ptr = std::unique_ptr<EC_KEY, std::function<decltype(EC_KEY_free)>>;

    static ECCImpl::Ptr genPair();
    static ECCImpl::Ptr fromPublicKey(const std::string& public_key);
    static ECCImpl::Ptr fromPrivateKey(const std::string& private_key);
    ECCImpl();
    ECCImpl(const ECCImpl& obj);
    ECCImpl(ECCImpl&& obj);
    ECCImpl(ec_key_unique_ptr&& key, bool has_priv);
    ECCImpl& operator=(const ECCImpl& obj);
    ECCImpl& operator=(ECCImpl&& obj);
    operator bool() const override;
    bool isEmpty() const override;
    std::string getPublicKey(bool compact = true) const override;
    PointImpl::Ptr getPublicKey2() const override;
    std::string getPrivateKey() const override;
    BNImpl::Ptr getPrivateKey2() const override;
    std::string sign(const std::string& data) const override;
    Signature sign2(const std::string& data) const override;
    bool verify(const std::string& data, const std::string& signature) const override;
    bool verify2(const std::string& data, const Signature& signature) const override;
    std::string derive(const ECCImpl::Ptr ecc) const override;
    std::string getOrder() const override;
    BNImpl::Ptr getOrder2() const override;
    PointImpl::Ptr getGenerator() const override;
    BNImpl::Ptr getEcOrder() const override;
    PointImpl::Ptr getEcGenerator() const override;
    const EC_POINT* getEcPoint() const;
    bool hasPrivate() const override { return _has_priv; }

private:
    using bignum_unique_ptr = std::unique_ptr<BIGNUM, std::function<decltype(BN_free)>>;
    using bn_ctx_unique_ptr = std::unique_ptr<BN_CTX, std::function<decltype(BN_CTX_free)>>;
    using ec_point_unique_ptr = std::unique_ptr<EC_POINT, std::function<decltype(EC_POINT_free)>>;
    using ecdsa_sig_unique_ptr = std::unique_ptr<ECDSA_SIG, std::function<decltype(ECDSA_SIG_free)>>;
    using ec_group_unique_ptr = std::unique_ptr<EC_GROUP, std::function<decltype(EC_GROUP_free)>>;

    static ec_key_unique_ptr newEcKey();
    static ec_key_unique_ptr copyEcKey(const ec_key_unique_ptr& key);
    static bignum_unique_ptr newBignum();
    static bignum_unique_ptr copyBignum(const BIGNUM* raw_bn);
    static bn_ctx_unique_ptr newBnCtx();
    static ec_point_unique_ptr copyEcPoint(const EC_POINT* raw_point, const EC_GROUP* group);
    static ec_point_unique_ptr newEcPoint(const EC_GROUP* group);
    static void setPublicKey(const ec_key_unique_ptr& key, const ec_point_unique_ptr& public_point);
    static void setPrivateKey(const ec_key_unique_ptr& key, const bignum_unique_ptr& private_key);
    static void checkKey(const ec_key_unique_ptr& key);
    static ec_point_unique_ptr mul(ec_key_unique_ptr& key);
    static bignum_unique_ptr bin2bignum(const std::string& bin);
    static ec_point_unique_ptr oct2point(const ec_key_unique_ptr& key, const std::string& oct);
    static ec_group_unique_ptr getEcGroup();
    EC_KEY* checkIfInitializedKeyAndGet() const;

    ec_key_unique_ptr _key;
    bool _has_priv = false;
};

inline ECCImpl::operator bool() const {
    return !isEmpty();
}

inline bool ECCImpl::isEmpty() const {
    return _key.get() == nullptr;
}

inline const EC_POINT* ECCImpl::getEcPoint() const {
    const EC_KEY* raw_key = checkIfInitializedKeyAndGet();
    return EC_KEY_get0_public_key(raw_key);
}

} // opensslimpl
} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_OPENSSL_ECCIMPL_HPP_
