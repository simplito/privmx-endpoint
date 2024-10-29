#ifndef _PRIVMXLIB_CRYPTO_ECCIMPL_HPP_
#define _PRIVMXLIB_CRYPTO_ECCIMPL_HPP_

#include <string>
#include <Poco/SharedPtr.h>

#include <privmx/crypto/ecc/BNImpl.hpp>
#include <privmx/crypto/ecc/PointImpl.hpp>

namespace privmx {
namespace crypto {

class ECCImpl
{
public:
    struct Signature
    {
        BNImpl::Ptr r;
        BNImpl::Ptr s;
    };

    using Ptr = Poco::SharedPtr<ECCImpl>;

    static ECCImpl::Ptr genPair();
    static ECCImpl::Ptr fromPublicKey(const std::string& public_key);
    static ECCImpl::Ptr fromPrivateKey(const std::string& private_key);
    virtual ~ECCImpl() = default;
    virtual operator bool() const = 0;
    virtual bool isEmpty() const = 0;
    virtual std::string getPublicKey(bool compact = true) const = 0;
    virtual PointImpl::Ptr getPublicKey2() const = 0;
    virtual std::string getPrivateKey() const = 0;
    virtual BNImpl::Ptr getPrivateKey2() const = 0;
    virtual std::string sign(const std::string& data) const = 0;
    virtual Signature sign2(const std::string& data) const = 0;
    virtual bool verify(const std::string& data, const std::string& signature) const = 0;
    virtual bool verify2(const std::string& data, const Signature& signature) const = 0;
    virtual std::string derive(const ECCImpl::Ptr ecc) const = 0;
    virtual std::string getOrder() const = 0;
    virtual BNImpl::Ptr getOrder2() const = 0;
    virtual PointImpl::Ptr getGenerator() const = 0;
    virtual BNImpl::Ptr getEcOrder() const  = 0;
    virtual PointImpl::Ptr getEcGenerator() const = 0;
    virtual bool hasPrivate() const = 0;

};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_ECCIMPL_HPP_
