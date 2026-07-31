/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_BASEMODULEDATASCHEMAMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_BASEMODULEDATASCHEMAMAPPER_HPP_

#include <type_traits>

#include <Poco/Dynamic/Var.h>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/DataSchemaMapperUtils.hpp>
#include <privmx/endpoint/core/encryptors/module/Constants.hpp>
#include <privmx/endpoint/core/encryptors/module/DynamicTypes.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV5.hpp>
#include <privmx/endpoint/core/encryptors/module/Types.hpp>

namespace privmx {
namespace endpoint {
namespace core {

class BaseModuleDataSchemaMapper {
public:
    BaseModuleDataSchemaMapper(const privmx::crypto::PrivateKey& userPrivKey, const core::Connection& connection)
        : _userPrivKey(userPrivKey), _connection(connection) {}
    virtual ~BaseModuleDataSchemaMapper() = default;

    template<typename TEntry>
    core::ModuleDataSchema::Version getDataStructureVersion(const TEntry& entry) const {
        if constexpr (std::is_same_v<std::decay_t<decltype(entry.data)>, Poco::Dynamic::Var>) {
            return getVersionFromVar(entry.data);
        } else {
            // Inbox special Case
            return getVersionFromVar(entry.data.meta);
        }
    }

    virtual core::ModuleInternalMetaV5 decryptInternalMeta(
        const Poco::Dynamic::Var& data,
        const core::DecryptedEncKey& encKey
    ) {
        if (getVersionFromVar(data) != core::ModuleDataSchema::Version::VERSION_5)
            return {};
        if (encKey.statusCode != 0)
            return {};
        return _encryptorV5.decrypt(core::dynamic::EncryptedModuleDataV5::fromJSON(data), encKey.key).internalMeta;
    }

protected:
    privmx::crypto::PrivateKey _userPrivKey;
    core::Connection _connection;
    core::ModuleDataEncryptorV5 _encryptorV5;

private:
    core::ModuleDataSchema::Version getVersionFromVar(const Poco::Dynamic::Var& data) const {
        return core::DataSchemaMapperUtils::mapVersionedData(
            data, core::ModuleDataSchema::Version::UNKNOWN,
            [](int64_t v) { return static_cast<core::ModuleDataSchema::Version>(v); }
        );
    }
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_BASEMODULEDATASCHEMAMAPPER_HPP_
