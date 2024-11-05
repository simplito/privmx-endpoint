/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_EMSCRIPTEN_BNIMPl_HPP_
#define _PRIVMXLIB_CRYPTO_EMSCRIPTEN_BNIMPl_HPP_

#include <functional>
#include <memory>
#include <string>
#include <Poco/SharedPtr.h>

#include <privmx/crypto/ecc/BNImpl.hpp>

namespace privmx {
namespace crypto {
namespace emscriptenimpl {

class BNImpl : public privmx::crypto::BNImpl
{
public:
    static BNImpl::Ptr fromBuffer(const std::string& data);
    static BNImpl::Ptr getDefault();
    BNImpl() = default;
    BNImpl(const BNImpl& obj);
    BNImpl(BNImpl&& obj);
    BNImpl(const std::string& bn);
    BNImpl& operator=(const BNImpl& obj);
    BNImpl& operator=(BNImpl&& obj);
    operator bool() const override;
    bool isEmpty() const override;
    std::string toBuffer() const override;
    std::size_t getBitsLength() const override;
    privmx::crypto::BNImpl::Ptr umod(const privmx::crypto::BNImpl::Ptr bn) const override;
    bool eq(const privmx::crypto::BNImpl::Ptr bn) const override;

private:
    void validate() const;

    std::string _bn;
};

inline BNImpl::operator bool() const {
    return !isEmpty();
}

inline bool BNImpl::isEmpty() const {
    return _bn.empty();
}

} // emscriptenimpl
} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_EMSCRIPTEN_BNIMPl_HPP_
