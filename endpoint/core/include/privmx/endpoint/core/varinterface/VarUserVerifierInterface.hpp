#ifndef _PRIVMXLIB_ENDPOINT_CORE_VARUSERVERIFIERINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_VARUSERVERIFIERINTERFACE_HPP_

#include <string>
#include <functional>
#include <privmx/utils/Debug.hpp>
#include "privmx/endpoint/core/UserVerifierInterface.hpp"
#include "privmx/endpoint/core/VarDeserializer.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class VarUserVerifierInterface: public virtual UserVerifierInterface {
private:
    std::function<Poco::Dynamic::Var(const Poco::Dynamic::Var&)> _verifierCallback;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
public:
    VarUserVerifierInterface(
        const std::function<Poco::Dynamic::Var(const Poco::Dynamic::Var&)>& verifierCallback,
        const core::VarDeserializer& deserializer,
        const core::VarSerializer& serializer
    ) : _verifierCallback(verifierCallback), _deserializer(deserializer), _serializer(serializer) {}
    std::vector<bool> verify(const std::vector<VerificationRequest>& request) override {
        auto serializedRequest = _serializer.serialize(request);
        auto result = _verifierCallback(serializedRequest);
        return _deserializer.deserializeVector<bool>(result, "validationResult");
    }
};


}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_VARUSERVERIFIERINTERFACE_HPP_
