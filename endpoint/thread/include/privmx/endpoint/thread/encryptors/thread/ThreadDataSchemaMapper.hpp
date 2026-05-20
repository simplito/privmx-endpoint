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
#include <string>
#include <tuple>
#include <vector>

#include <Poco/Dynamic/Var.h>
#include <privmx/crypto/ecc/PrivateKey.hpp>
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

class ThreadDataSchemaMapper {
public:
    ThreadDataSchemaMapper(const privmx::crypto::PrivateKey& userPrivKey, const core::Connection& connection);

    Poco::Dynamic::Var encrypt(const core::ModuleDataToEncryptV5& data, const std::string& key);

    std::tuple<Thread, core::DataIntegrityObject> decrypt(
        const server::ThreadInfo& thread,
        const core::DecryptedEncKey& encKey
    );

    ThreadDataSchema::Version getDataStructureVersion(const server::Thread2DataEntry& entry);

    void assertDataIntegrity(const server::ThreadInfo& thread);

    uint32_t validateDataIntegrity(const server::ThreadInfo& thread);

    std::vector<Thread> validateDecryptAndConvertThreads(
        const std::vector<server::ThreadInfo>& threads,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );

    Thread validateDecryptAndConvertThread(
        const server::ThreadInfo& thread,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );

    static Thread toLibThread(
        const server::ThreadInfo& info,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        int64_t statusCode,
        int64_t schemaVersion
    );

private:
    privmx::crypto::PrivateKey _userPrivKey;
    core::Connection _connection;
    core::VersionStrategyMapper<server::ThreadInfo, std::tuple<Thread, core::DataIntegrityObject>> _strategyMapper;
    std::shared_ptr<ThreadDataSchemaStrategyV5> _strategyV5;
};

} // namespace thread
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADDATASCHEMAMAPPER_HPP_
