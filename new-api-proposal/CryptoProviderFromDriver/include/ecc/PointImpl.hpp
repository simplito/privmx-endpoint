/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_POINTIMPL_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_POINTIMPL_HPP_

#include <functional>
#include <memory>
#include <string>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include <Poco/SharedPtr.h>

#include "BN.hpp"


namespace privmx {
namespace cryptoservice {
namespace ecc {


class PointImpl 
{
public:
    // using Ptr = Poco::SharedPtr<PointImpl>;
    using Ptr = std::shared_ptr<PointImpl>;
    using ec_point_unique_ptr = std::unique_ptr<EC_POINT, std::function<decltype(EC_POINT_free)>>;

    static PointImpl::Ptr fromBuffer(const std::string& data);
    static PointImpl::Ptr getDefault();
    PointImpl() = default;
    PointImpl(const PointImpl& obj);
    PointImpl(PointImpl&& obj);
    PointImpl(ec_point_unique_ptr&& bn);
    PointImpl& operator=(const PointImpl& obj);
    PointImpl& operator=(PointImpl&& obj);
    operator bool() const;
    bool isEmpty() const;
    std::string encode(bool compact = false) const;
    PointImpl::Ptr mul(const BNImpl::Ptr bn) const;
    PointImpl::Ptr add(const PointImpl::Ptr point) const;
    const EC_POINT* getRaw() const;

    // new methods
    static PointImpl::Ptr fromBuffer(BytesView data);

private:
    using ec_group_unique_ptr = std::unique_ptr<EC_GROUP, std::function<decltype(EC_GROUP_free)>>;
    using bn_ctx_unique_ptr = std::unique_ptr<BN_CTX, std::function<decltype(BN_CTX_free)>>;

    static ec_point_unique_ptr oct2point(const std::string& oct);
    static ec_point_unique_ptr copyEcPoint(const ec_point_unique_ptr& point);
    static ec_point_unique_ptr newEcPoint();
    static ec_group_unique_ptr getEcGroup();
    static bn_ctx_unique_ptr newBnCtx();
    void validate() const;

    ec_point_unique_ptr _point;

    // new methods
    static ec_point_unique_ptr oct2point(BytesView oct);
};

inline PointImpl::operator bool() const {
    return !isEmpty();
}

inline bool PointImpl::isEmpty() const {
    return !_point;
}

} // ecc
} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_POINTIMPL_HPP_