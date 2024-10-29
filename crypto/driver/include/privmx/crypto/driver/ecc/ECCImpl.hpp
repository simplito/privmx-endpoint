#ifndef _PRIVMXLIB_CRYPTO_DRIVER_ECCIMPL_HPP_
#define _PRIVMXLIB_CRYPTO_DRIVER_ECCIMPL_HPP_

#include <functional>
#include <memory>
#include <string>
#include <Poco/SharedPtr.h>

#include <privmx/drv/ecc.h>

#include <privmx/crypto/ecc/ECCImpl.hpp>
#include <privmx/crypto/driver/ecc/BNImpl.hpp>
#include <privmx/crypto/driver/ecc/PointImpl.hpp>

namespace privmx {
namespace crypto {
namespace driverimpl {

class ECCImpl : public privmx::crypto::ECCImpl
{
public:
    using ec_key_unique_ptr = std::unique_ptr<privmxDrvEcc_ECC, std::function<decltype(privmxDrvEcc_eccFree)>>;

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
    bool hasPrivate() const override { return _has_priv; }

private:
    static ec_key_unique_ptr copyEcKey(const ec_key_unique_ptr& key);
    void validate() const;

    ec_key_unique_ptr _key;
    bool _has_priv = false;
};

inline ECCImpl::operator bool() const {
    return !isEmpty();
}

inline bool ECCImpl::isEmpty() const {
    return _key.get() == nullptr;
}

} // driverimpl
} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_DRIVER_ECCIMPL_HPP_
