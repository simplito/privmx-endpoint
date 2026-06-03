/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_DATASCHEMAMAPPERUTILS_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_DATASCHEMAMAPPERUTILS_HPP_

#include <functional>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <Poco/JSON/Object.h>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/encryptors/module/DynamicTypes.hpp>
#include <privmx/utils/PrivmxException.hpp>

namespace privmx {
namespace endpoint {
namespace core {

template<typename T> struct type_identity { using type = T; };
template<typename T> using type_identity_t = typename type_identity<T>::type;

class DataSchemaMapperUtils {
public:
    static uint32_t toStatusCode(std::function<void()> fn) noexcept {
        try { fn(); return 0; }
        catch (const Exception& e) { return e.getCode(); }
        catch (const privmx::utils::PrivmxException& e) { return ExceptionConverter::convert(e).getCode(); }
        catch (...) { return ENDPOINT_CORE_EXCEPTION_CODE; }
    }

    template<typename TContainer>
    static auto assertContainerDIOIntegrity(
        const DataIntegrityObject& dio,
        const TContainer& c,
        std::function<void()> throwOnFail
    ) -> decltype(c.contextId, c.resourceId, c.lastModifier, c.lastModificationDate, void()) {
        if (dio.contextId != c.contextId ||
            dio.resourceId != c.resourceId ||
            dio.creatorUserId != c.lastModifier ||
            !TimestampValidator::validate(dio.timestamp, c.lastModificationDate)) {
            throwOnFail();
        }
    }

    static void assertEntryDIOIntegrity(
        const DataIntegrityObject& dio,
        const std::string& contextId,
        const std::string& resourceId,
        const std::string& containerId,
        const std::string& containerResourceId,
        const std::string& creatorUserId,
        int64_t date,
        std::function<void()> throwOnFail
    ) {
        if (dio.contextId != contextId ||
            dio.resourceId != resourceId ||
            !dio.containerId || dio.containerId.value() != containerId ||
            !dio.containerResourceId || dio.containerResourceId.value() != containerResourceId ||
            dio.creatorUserId != creatorUserId ||
            !TimestampValidator::validate(dio.timestamp, date)) {
            throwOnFail();
        }
    }

    template<typename TContainer, typename TStrategyV5>
    static void assertContainerV5DIOIntegrity(
        const Poco::Dynamic::Var& data,
        const TContainer& container,
        const std::shared_ptr<TStrategyV5>& strategyV5,
        std::function<void()> throwOnFail
    ) {
        auto encData = dynamic::EncryptedModuleDataV5::fromJSON(data);
        assertContainerDIOIntegrity(strategyV5->getDIOAndAssertIntegrity(encData), container, throwOnFail);
    }

    template<typename VersionEnum>
    static VersionEnum mapVersionedData(const Poco::Dynamic::Var& var, VersionEnum unknown, type_identity_t<std::function<VersionEnum(int64_t)>> mapper) {
        if (var.type() == typeid(Poco::JSON::Object::Ptr)) {
            return mapper(dynamic::VersionedData::fromJSON(var).version);
        }
        return unknown;
    }

    template<typename TLib, typename TServer>
    [[nodiscard]] static std::vector<TLib> batchValidateDecryptVerifyContainers(
        const std::vector<TServer>& items,
        const std::shared_ptr<KeyProvider>& keyProvider,
        const Connection& connection,
        std::function<uint32_t(const type_identity_t<TServer>&)> validateIntegrity,
        std::function<EncKeyLocation(const type_identity_t<TServer>&)> getLocation,
        std::function<std::tuple<type_identity_t<TLib>, DataIntegrityObject>(const type_identity_t<TServer>&, const DecryptedEncKey&)> decrypt,
        std::function<type_identity_t<TLib>(const type_identity_t<TServer>&, uint32_t)> toLibError
    ) {
        if (items.empty()) {
            return std::vector<TLib>{};
        }

        std::vector<TLib> result(items.size());
        std::vector<DataIntegrityObject> dios(items.size());

        for (size_t i = 0; i < items.size(); i++) {
            if (auto code = validateIntegrity(items[i]); code != 0) {
                result[i] = toLibError(items[i], code);
            }
        }

        KeyDecryptionAndVerificationRequest keyRequest;
        for (size_t i = 0; i < items.size(); i++) {
            if (result[i].statusCode != 0) {
                continue;
            }
            keyRequest.addOne(items[i].keys, items[i].data.back().keyId, getLocation(items[i]));
        }
        auto allKeys = keyProvider->getKeysAndVerify(keyRequest);
        std::set<std::string> seenRandomIds;

        for (size_t i = 0; i < items.size(); i++) {
            if (result[i].statusCode != 0) {
                continue;
            }
            try {
                if (auto it = allKeys.find(getLocation(items[i])); it != allKeys.end()) {
                    auto [lib, dio] = decrypt(items[i], it->second.at(items[i].data.back().keyId));
                    result[i] = lib;
                    dios[i] = dio;
                    if (!seenRandomIds.insert(dio.randomId + "-" + std::to_string(dio.timestamp)).second) {
                        result[i].statusCode = DataIntegrityObjectDuplicatedException().getCode();
                    }
                } else {
                    result[i] = toLibError(items[i], ENDPOINT_CORE_EXCEPTION_CODE);
                }
            } catch (const Exception& e) {
                result[i] = toLibError(items[i], e.getCode());
            } catch (const privmx::utils::PrivmxException& e) {
                result[i] = toLibError(items[i], ExceptionConverter::convert(e).getCode());
            } catch (...) {
                result[i] = toLibError(items[i], ENDPOINT_CORE_EXCEPTION_CODE);
            }
        }

        std::vector<VerificationRequest> verifyReqs;
        std::vector<size_t> verifyIdxs;
        for (size_t i = 0; i < result.size(); i++) {
            if (result[i].statusCode != 0) {
                continue;
            }
            verifyReqs.push_back(
                {.contextId = result[i].contextId,
                 .senderId = result[i].lastModifier,
                 .senderPubKey = dios[i].creatorPubKey,
                 .date = result[i].lastModificationDate,
                 .bridgeIdentity = dios[i].bridgeIdentity}
            );
            verifyIdxs.push_back(i);
        }
        auto verified = connection.getImpl()->getUserVerifier()->verify(verifyReqs);
        for (size_t j = 0; j < verifyIdxs.size(); j++) {
            result[verifyIdxs[j]].statusCode =
                verified[j] ? 0 : ExceptionConverter::getCodeOfUserVerificationFailureException();
        }
        return result;
    }

    template<typename TLib, typename TServer>
    [[nodiscard]] static std::vector<TLib> batchValidateDecryptVerifyEntries(
        const std::vector<TServer>& items,
        const ModuleKeys& moduleKeys,
        const std::shared_ptr<KeyProvider>& keyProvider,
        const Connection& connection,
        std::function<uint32_t(const type_identity_t<TServer>&)> validateIntegrity,
        std::function<uint32_t(const type_identity_t<TServer>&)> validateKeyId,
        std::function<std::tuple<type_identity_t<TLib>, DataIntegrityObject>(const type_identity_t<TServer>&, const DecryptedEncKey&)> decrypt,
        std::function<type_identity_t<TLib>(const type_identity_t<TServer>&, uint32_t)> toLibError
    ) {
        if (items.empty()) {
            return std::vector<TLib>{};
        }

        std::vector<TLib> result(items.size());
        std::vector<DataIntegrityObject> dios(items.size());

        for (size_t i = 0; i < items.size(); i++) {
            if (auto code = validateIntegrity(items[i]); code != 0) {
                result[i] = toLibError(items[i], code);
            }
        }

        const EncKeyLocation location{.contextId = moduleKeys.contextId, .resourceId = moduleKeys.moduleResourceId};
        KeyDecryptionAndVerificationRequest keyRequest;
        for (size_t i = 0; i < items.size(); i++) {
            if (result[i].statusCode != 0) {
                continue;
            }
            if (auto code = validateKeyId(items[i]); code != 0) {
                result[i] = toLibError(items[i], code);
                continue;
            }
            keyRequest.addOne(moduleKeys.keys, items[i].keyId, location);
        }
        auto allKeys = keyProvider->getKeysAndVerify(keyRequest);
        const auto keyMapIt = allKeys.find(location);
        const auto* keyMap = keyMapIt != allKeys.end() ? &keyMapIt->second : nullptr;
        std::set<std::string> seenRandomIds;

        for (size_t i = 0; i < items.size(); i++) {
            if (result[i].statusCode != 0) {
                continue;
            }
            try {
                if (!keyMap) {
                    result[i] = toLibError(items[i], ENDPOINT_CORE_EXCEPTION_CODE);
                    continue;
                }
                auto [lib, dio] = decrypt(items[i], keyMap->at(items[i].keyId));
                result[i] = lib;
                dios[i] = dio;
                if (!seenRandomIds.insert(dio.randomId + "-" + std::to_string(dio.timestamp)).second) {
                    result[i].statusCode = DataIntegrityObjectDuplicatedException().getCode();
                }
            } catch (const Exception& e) {
                result[i] = toLibError(items[i], e.getCode());
            } catch (const privmx::utils::PrivmxException& e) {
                result[i] = toLibError(items[i], ExceptionConverter::convert(e).getCode());
            } catch (...) {
                result[i] = toLibError(items[i], ENDPOINT_CORE_EXCEPTION_CODE);
            }
        }

        std::vector<VerificationRequest> verifyReqs;
        std::vector<size_t> verifyIdxs;
        for (size_t i = 0; i < result.size(); i++) {
            if (result[i].statusCode != 0) {
                continue;
            }
            verifyReqs.push_back(
                {.contextId = moduleKeys.contextId,
                 .senderId = result[i].info.author,
                 .senderPubKey = result[i].authorPubKey,
                 .date = result[i].info.createDate,
                 .bridgeIdentity = dios[i].bridgeIdentity}
            );
            verifyIdxs.push_back(i);
        }
        auto verified = connection.getImpl()->getUserVerifier()->verify(verifyReqs);
        for (size_t j = 0; j < verifyIdxs.size(); j++) {
            result[verifyIdxs[j]].statusCode =
                verified[j] ? 0 : ExceptionConverter::getCodeOfUserVerificationFailureException();
        }
        return result;
    }

    template<typename TLib, typename TServer>
    [[nodiscard]] static std::vector<TLib> batchValidateDecryptVerifyEntries(
        const std::vector<TServer>& items,
        const ModuleKeys& moduleKeys,
        const std::shared_ptr<KeyProvider>& keyProvider,
        const Connection& connection,
        std::function<uint32_t(const type_identity_t<TServer>&)> validateIntegrity,
        std::function<std::tuple<type_identity_t<TLib>, DataIntegrityObject>(const type_identity_t<TServer>&, const DecryptedEncKey&)> decrypt,
        std::function<type_identity_t<TLib>(const type_identity_t<TServer>&, uint32_t)> toLibError
    ) {
        return batchValidateDecryptVerifyEntries<TLib, TServer>(
            items, moduleKeys, keyProvider, connection,
            validateIntegrity,
            std::function<uint32_t(const TServer&)>([](const TServer&) -> uint32_t { return 0; }),
            decrypt,
            toLibError
        );
    }
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_DATASCHEMAMAPPERUTILS_HPP_
