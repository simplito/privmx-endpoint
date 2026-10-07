/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_THREADDATASCHEMAMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_THREADDATASCHEMAMAPPER_HPP_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <Poco/Dynamic/Var.h>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/BaseModuleDataSchemaMapper.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/encryptors/VersionStrategyMapper.hpp>
#include <privmx/endpoint/core/encryptors/module/Types.hpp>

#include "privmx/endpoint/thread/Constants.hpp"
#include "privmx/endpoint/thread/ServerTypes.hpp"
#include "privmx/endpoint/thread/Types.hpp"
#include "privmx/endpoint/thread/encryptors/thread/ThreadDataSchemaStrategyV4.hpp"
#include "privmx/endpoint/thread/encryptors/thread/ThreadDataSchemaStrategyV5.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class ThreadDataSchemaMapper : public core::BaseModuleDataSchemaMapper {
public:
    ThreadDataSchemaMapper(const core::PrivateKey& userPrivKey, const core::Connection& connection);

    Poco::Dynamic::Var encrypt(const core::ModuleDataToEncryptV5& data, const core::EncKey& key);

    std::tuple<Thread, core::DataIntegrityObject> decrypt(
        const server::ThreadInfo& thread,
        const core::DecryptedEncKey& encKey,
        const std::optional<core::DataIntegrityObject>& verifiedDio = std::nullopt
    );

    // Returns the head entry's DIO for a V5 thread, so the decrypt that follows need not verify it again.
    // Empty for V4, which carries no DIO at all.
    std::optional<core::DataIntegrityObject> assertDataIntegrity(const server::ThreadInfo& thread);

    std::pair<uint32_t, std::optional<core::DataIntegrityObject>> validateDataIntegrity(
        const server::ThreadInfo& thread
    );

    std::vector<Thread> validateDecryptAndConvertThreads(
        const std::vector<server::ThreadInfo>& threads,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver = nullptr
    );

    Thread validateDecryptAndConvertThread(
        const server::ThreadInfo& thread,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver = nullptr
    );

    static Thread toLibThread(
        const server::ThreadInfo& info,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        int64_t statusCode,
        int64_t schemaVersion
    );

private:
    core::VersionStrategyMapper<server::ThreadInfo, std::tuple<Thread, core::DataIntegrityObject>> _strategyMapper;
    std::shared_ptr<ThreadDataSchemaStrategyV5> _strategyV5;
};

} // namespace thread
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADDATASCHEMAMAPPER_HPP_
