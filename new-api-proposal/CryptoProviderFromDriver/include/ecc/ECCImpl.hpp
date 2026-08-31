/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_ECCIMPL_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_ECCIMPL_HPP_

#include <functional>
#include <memory>
#include <string>
#include <openssl/bn.h>
#include <Poco/SharedPtr.h>

#include "BNImpl.hpp"
#include "PointImpl.hpp"
// #include "ECCImpl.hpp"

#include "CoreTypes.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

class ECCImpl
{
public:
    struct Signature
    {
        BNImpl::Ptr r;
        BNImpl::Ptr s;
    };

    // using Ptr = Poco::SharedPtr<ECCImpl>;
    using Ptr = std::shared_ptr<ECCImpl>;
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
    operator bool() const;
    bool isEmpty() const;
    std::string getPublicKey(bool compact = true) const;
    PointImpl::Ptr getPublicKey2() const;
    std::string getPrivateKey() const;
    BNImpl::Ptr getPrivateKey2() const;
    std::string sign(const std::string& data) const;
    Signature sign2(const std::string& data) const;
    bool verify(const std::string& data, const std::string& signature) const;
    bool verify2(const std::string& data, const Signature& signature) const;
    std::string derive(const ECCImpl::Ptr ecc) const;
    std::string getOrder() const;
    BNImpl::Ptr getOrder2() const;
    PointImpl::Ptr getGenerator() const;
    BNImpl::Ptr getEcOrder() const;
    PointImpl::Ptr getEcGenerator() const;
    const EC_POINT* getEcPoint() const;
    bool hasPrivate() const { return _has_priv; }

    // new methods
    static ECCImpl::Ptr fromPublicKey(BytesView public_key);
    static ECCImpl::Ptr fromPrivateKey(BytesView private_key);
    Bytes getPrivateKeyB() const;
    Bytes getPublicKeyB(bool compact = true) const;
    Bytes sign(BytesView data) const;
    Signature sign2(BytesView data) const;
    bool verify(BytesView data, BytesView signature) const;
    bool verify2(BytesView data, const Signature& signature) const;
    Bytes getOrderB() const;

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

    static bignum_unique_ptr bin2bignum(BytesView bin);
    static ec_point_unique_ptr oct2point(const ec_key_unique_ptr& key, BytesView oct);


    // // Probably to be removed:
    // void validate() const;
    
    // // Probably to be removed:
    // struct privmxDrvEcc_BN {
    //     std::unique_ptr<BIGNUM, decltype(&BN_free)> impl;
    // };
    // struct privmxDrvEcc_ECC {
    //     std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> impl;
    // };
    // struct privmxDrvEcc_Signature
    // {
    //     const privmxDrvEcc_BN* r;
    //     const privmxDrvEcc_BN* s;
    // };
    // int privmxDrvEcc_eccSign(privmxDrvEcc_ECC* ecc, const char* msg, int msglen, privmxDrvEcc_Signature* res);
    // int privmxDrvEcc_eccSign(const ec_key_unique_ptr& _ecc, const char* msg, int msglen, privmxDrvEcc_Signature* res);
    // int privmxDrvEcc_eccSign(ec_key_unique_ptr _ecc, const char* msg, int msglen, privmxDrvEcc_Signature* res);
    // int privmxDrvEcc_eccSign(const char* msg, int msglen, privmxDrvEcc_Signature* res);
    // int privmxDrvEcc_eccSign(std::string data, privmxDrvEcc_Signature* res);
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

} // ecc
} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_ECCIMPL_HPP_