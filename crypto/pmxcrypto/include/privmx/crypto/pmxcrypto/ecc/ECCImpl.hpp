/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_PMXCRYPTO_ECCIMPL_HPP_
#define _PRIVMXLIB_CRYPTO_PMXCRYPTO_ECCIMPL_HPP_

#include <memory>
#include <string>

#include <privmx/cryptoservice/base/CoreInterfaces.hpp>

#include <privmx/crypto/ecc/ECCImpl.hpp>

namespace privmx {
namespace crypto {
namespace pmximpl {

/**
 * @brief `privmx::crypto::ECCImpl` backed by pmx-crypto.
 *
 * The curve is secp256k1 in PrivMX's data formats — `AsymAlg::PrivmxSecp256k1`. That is not a
 * choice made here: the old stack knows one curve and never had a parameter for it.
 *
 * Keys are held as pmx-crypto's immutable handles, so copying shares them rather than duplicating
 * the underlying key — which is all `ECC` needs, since it only ever shared its impl pointer.
 */
class ECCImpl : public privmx::crypto::ECCImpl
{
public:
    static ECCImpl::Ptr genPair();
    static ECCImpl::Ptr fromPublicKey(const std::string& public_key);
    static ECCImpl::Ptr fromPrivateKey(const std::string& private_key);

    ECCImpl() = default;
    ECCImpl(
        std::shared_ptr<privmx::cryptoservice::IPrivateKey> priv,
        std::shared_ptr<privmx::cryptoservice::IPublicKey> pub
    );

    operator bool() const override;
    bool isEmpty() const override;
    std::string getPublicKey(bool compact = true) const override;
    std::string getPrivateKey() const override;
    std::string sign(const std::string& data) const override;
    bool verify(const std::string& data, const std::string& signature) const override;
    std::string derive(const privmx::crypto::ECCImpl::Ptr ecc) const override;
    std::string getOrder() const override;
    bool hasPrivate() const override;

    std::shared_ptr<privmx::cryptoservice::IPublicKey> publicKeyHandle() const { return _pub; }

private:
    void validate() const;

    std::shared_ptr<privmx::cryptoservice::IPrivateKey> _priv;
    std::shared_ptr<privmx::cryptoservice::IPublicKey> _pub;
};

} // namespace pmximpl
} // namespace crypto
} // namespace privmx

#endif // _PRIVMXLIB_CRYPTO_PMXCRYPTO_ECCIMPL_HPP_
