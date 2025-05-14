/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_VARSERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_VARSERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <Pson/BinaryString.hpp>
#include <privmx/utils/Utils.hpp>
#include <string>

#include "privmx/endpoint/core/BufferVarHolderImpl.hpp"
#include "privmx/endpoint/core/Events.hpp"
#include "privmx/endpoint/core/Exception.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/core/UserVerifierInterface.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class VarSerializer {
public:
    struct Options {
        bool addType = false;
        enum { CORE_BUFFER, PSON_BINARYSTRING, STD_STRING_AS_BASE64, STD_STRING } binaryFormat = CORE_BUFFER;
    };

    VarSerializer(const Options& options) : _options(std::move(options)) {}
    template<typename T>
    Poco::Dynamic::Var serialize(const T& value) = delete;
    template<typename T>
    Poco::Dynamic::Var serialize(const std::vector<T>& value);
    template<typename T>
    Poco::Dynamic::Var serialize(const std::optional<T>& value);

    const Options& getOptions() const {
        return _options;
    }
private:
    const Options _options;
};

template<typename T>
inline Poco::Dynamic::Var VarSerializer::serialize(const std::vector<T>& val) {
    Poco::JSON::Array::Ptr arr = new Poco::JSON::Array();
    for (const auto& item : val) {
        arr->add(serialize(item));
    }
    return arr;
}

template<typename T>
inline Poco::Dynamic::Var VarSerializer::serialize(const std::optional<T>& val) {
    if (val.has_value()) {
        return serialize(val.value());
    }
    return Poco::Dynamic::Var();
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<int64_t>(const int64_t& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<std::string>(const std::string& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<Buffer>(const core::Buffer& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<bool>(const bool& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<Context>(const Context& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<PagingList<Context>>(const PagingList<Context>& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<LibPlatformDisconnectedEvent>(const LibPlatformDisconnectedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<LibConnectedEvent>(const LibConnectedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<LibDisconnectedEvent>(const LibDisconnectedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<LibBreakEvent>(const LibBreakEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<ContainerPolicyWithoutItem>(const ContainerPolicyWithoutItem& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<ItemPolicy>(const ItemPolicy& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<ContainerPolicy>(const ContainerPolicy& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<UserWithPubKey>(const UserWithPubKey& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<UserInfo>(const UserInfo& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<BridgeIdentity>(const BridgeIdentity& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<VerificationRequest>(const VerificationRequest& val);

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_VARSERIALIZER_HPP_
