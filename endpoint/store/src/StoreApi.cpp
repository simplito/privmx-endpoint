/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/store/StoreException.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include "privmx/endpoint/core/ExceptionConverter.hpp"

#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/store/StoreApiImpl.hpp"
#include "privmx/endpoint/store/StoreValidator.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

StoreApi::StoreApi() {};
StoreApi::StoreApi(const StoreApi& obj): ExtendedPointer(obj) {};
StoreApi& StoreApi::operator=(const StoreApi& obj) {
    this->ExtendedPointer::operator=(obj);
    return *this;
};
StoreApi::StoreApi(StoreApi&& obj): ExtendedPointer(std::move(obj)) {};
StoreApi::~StoreApi() {}

StoreApi StoreApi::create(core::Connection& connection) {
    try {
        std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
        std::shared_ptr<ServerApi> serverApi(new ServerApi(connectionImpl->getGateway()));
        std::shared_ptr<RequestApi> requestApi(new RequestApi(connectionImpl->getGateway()));
        std::shared_ptr<StoreApiImpl> impl(new StoreApiImpl(
            connectionImpl->getKeyProvider(),
            serverApi,
            connectionImpl->getHost(),
            connectionImpl->getUserPrivKey(),
            requestApi,
            std::shared_ptr<FileDataProvider>(new FileDataProvider(serverApi)),
            connectionImpl->getEventMiddleware(),
            connectionImpl->getHandleManager(),
            connection,
            connectionImpl->getServerConfig().requestChunkSize
        ));
        impl->attach(impl);
        return StoreApi(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StoreApi::StoreApi(const std::shared_ptr<StoreApiImpl>& impl) : ExtendedPointer(impl) {}

std::string StoreApi::createStore(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta, const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return impl->createStore(contextId, users, managers, publicMeta, privateMeta, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StoreApi::updateStore(
    const std::string& storeId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>& managers, 
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t version, 
    const bool force, 
    const bool forceGenerateNewKey,
    const std::optional<core::ContainerPolicy>& policies
)
{
    auto impl = getImpl();
    core::Validator::validateId(storeId, "field:storeId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        impl->updateStore(storeId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}


void StoreApi::deleteStore(const std::string& storeId) {
    auto impl = getImpl();
    core::Validator::validateId(storeId, "field:storeId ");
    try {
        return impl->deleteStore(storeId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Store StoreApi::getStore(const std::string& storeId) {
    auto impl = getImpl();
    core::Validator::validateId(storeId, "field:storeId ");
    try {
        return impl->getStore(storeId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<Store> StoreApi::listStores(const std::string& contextId, const core::PagingQuery& query) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(query, {"createDate", "lastModificationDate", "lastFileDate"}, "field:query ");
    try {
        return impl->listStores(contextId, query);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StoreApi::deleteFile(const std::string& fileId) {
    auto impl = getImpl();
    core::Validator::validateId(fileId, "field:fileId ");
    try {
        impl->deleteFile(fileId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t StoreApi::createFile(const std::string& storeId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t size, bool randomWriteSupport) {
    auto impl = getImpl();
    core::Validator::validateId(storeId, "field:storeId ");
    core::Validator::validateNumberNonNegative(size, "field:size ");
    try {
        return impl->createFile(storeId, publicMeta, privateMeta, size, randomWriteSupport);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t StoreApi::updateFile(const std::string& fileId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t size) {
    auto impl = getImpl();
    core::Validator::validateId(fileId, "field:fileId ");
    core::Validator::validateNumberNonNegative(size, "field:size ");
    try {
        return impl->updateFile(fileId, publicMeta, privateMeta, size);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t StoreApi::openFile(const std::string& fileId) {
    auto impl = getImpl();
    core::Validator::validateId(fileId, "field:fileId ");
    try {
        return impl->openFile(fileId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StoreApi::writeToFile(const int64_t handle, const core::Buffer& dataChunk, bool truncate) {
    auto impl = getImpl();
    try {
        return impl->writeToFile(handle, dataChunk, truncate);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::Buffer StoreApi::readFromFile(const int64_t handle, const int64_t length) {
    auto impl = getImpl();
    core::Validator::validateNumberNonNegative(length, "field:length ");
    try {
        return impl->readFromFile(handle, length);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StoreApi::seekInFile(const int64_t handle, const int64_t pos) {
    auto impl = getImpl();
    core::Validator::validateNumberNonNegative(pos, "field:pos ");
    try {
        return impl->seekInFile(handle, pos);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string StoreApi::closeFile(const int64_t handle) {
    auto impl = getImpl();
    try {
        return impl->closeFile(handle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

File StoreApi::getFile(const std::string& fileId) {
    auto impl = getImpl();
    core::Validator::validateId(fileId, "field:fileId ");
    try {
        return impl->getFile(fileId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<File> StoreApi::listFiles(const std::string& storeId, const core::PagingQuery& listQuery) {
    auto impl = getImpl();
    core::Validator::validateId(storeId, "field:storeId ");
    core::Validator::validatePagingQuery(listQuery, {"createDate", "updates"}, "field:listQuery ");
    try {
        return impl->listFiles(storeId, listQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StoreApi::updateFileMeta(const std::string& fileId, const core::Buffer& publicMeta, const core::Buffer& privateMeta) {
    auto impl = getImpl();
    core::Validator::validateId(fileId, "field:fileId ");
    try {
        return impl->updateFileMeta(fileId, publicMeta, privateMeta);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StoreApi::syncFile(const int64_t handle) {
    auto impl = getImpl();
    try {
        return impl->syncFile(handle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<std::string> StoreApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    try {
        return impl->subscribeFor(subscriptionQueries);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StoreApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    try {
        return impl->unsubscribeFrom(subscriptionIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string StoreApi::buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    auto impl = getImpl();
    try {
        return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
