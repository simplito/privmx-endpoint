#ifndef _PRIVMXLIB_ENDPOINT_CORE_BUFFERVARHOLDERIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_BUFFERVARHOLDERIMPL_HPP_

#include <Poco/Dynamic/VarHolder.h>

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/utils/Utils.hpp"

namespace Poco {
namespace Dynamic {

template<>
class VarHolderImpl<privmx::endpoint::core::Buffer> : public VarHolder {
public:
    VarHolderImpl(const privmx::endpoint::core::Buffer& val) : _val(val) {}
    ~VarHolderImpl() = default;
    const std::type_info& type() const override { return typeid(privmx::endpoint::core::Buffer); }
    void convert(std::string& val) const override { val = privmx::utils::Base64::from(_val.stdString()); }
    VarHolder* clone(Placeholder<VarHolder>* pVarHolder = 0) const override { return cloneHolder(pVarHolder, _val); }
    const privmx::endpoint::core::Buffer& value() const { return _val; }
    bool isString() const override { return true; }

private:
    VarHolderImpl();
    VarHolderImpl(const VarHolderImpl&);
    VarHolderImpl& operator=(const VarHolderImpl&);

    privmx::endpoint::core::Buffer _val;
};

}  // namespace Dynamic
}  // namespace Poco

#endif  // _PRIVMXLIB_ENDPOINT_CORE_BUFFERVARHOLDERIMPL_HPP_
