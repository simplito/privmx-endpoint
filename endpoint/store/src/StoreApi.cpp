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
#include "privmx/endpoint/store/StoreVarSerializer.hpp"
#include "privmx/endpoint/store/StoreValidator.hpp"
#include "privmx/endpoint/core/EventVarSerializer.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

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
            // std::shared_ptr<FilesUtils>(new FilesUtils(requestApi)),
            std::shared_ptr<FileDataProvider>(new FileDataProvider(serverApi)),
            connectionImpl->getEventMiddleware(),
            connectionImpl->getEventChannelManager(),
            // connectionImpl->getDataResolver(),
            connectionImpl->getHandleManager(),
            connection,
            connectionImpl->getServerConfig().requestChunkSize
        ));
        return StoreApi(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StoreApi::StoreApi(const std::shared_ptr<StoreApiImpl>& impl) : _impl(impl) {}

void StoreApi::validateEndpoint() {
    if(!_impl) throw NotInitializedException();
}

std::string StoreApi::createStore(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta, const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies) {
    validateEndpoint();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return _impl->createStore(contextId, users, managers, publicMeta, privateMeta, policies);
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
    validateEndpoint();
    core::Validator::validateId(storeId, "field:storeId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        _impl->updateStore(storeId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}


void StoreApi::deleteStore(const std::string& storeId) {
    validateEndpoint();
    core::Validator::validateId(storeId, "field:storeId ");
    try {
        return _impl->deleteStore(storeId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Store StoreApi::getStore(const std::string& storeId) {
    validateEndpoint();
    core::Validator::validateId(storeId, "field:storeId ");
    try {
        return _impl->getStore(storeId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<Store> StoreApi::listStores(const std::string& contextId, const core::PagingQuery& query) {
    validateEndpoint();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(query, {"createDate", "lastModificationDate", "lastFileDate"}, "field:query ");
    try {
        return _impl->listStores(contextId, query);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StoreApi::deleteFile(const std::string& fileId) {
    validateEndpoint();
    core::Validator::validateId(fileId, "field:fileId ");
    try {
        _impl->deleteFile(fileId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t StoreApi::createFile(const std::string& storeId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t size) {
    validateEndpoint();
    core::Validator::validateId(storeId, "field:storeId ");
    core::Validator::validateNumberNonNegative(size, "field:size ");
    try {
        return _impl->createFile(storeId, publicMeta, privateMeta, size);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t StoreApi::updateFile(const std::string& fileId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t size) {
    validateEndpoint();
    core::Validator::validateId(fileId, "field:fileId ");
    core::Validator::validateNumberNonNegative(size, "field:size ");
    try {
        return _impl->updateFile(fileId, publicMeta, privateMeta, size);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t StoreApi::openFile(const std::string& fileId) {
    validateEndpoint();
    core::Validator::validateId(fileId, "field:fileId ");
    try {
        return _impl->openFile(fileId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StoreApi::writeToFile(const int64_t handle, const core::Buffer& dataChunk) {
    validateEndpoint();
    try {
        return _impl->writeToFile(handle, dataChunk);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::Buffer StoreApi::readFromFile(const int64_t handle, const int64_t length) {
    validateEndpoint();
    core::Validator::validateNumberNonNegative(length, "field:length ");
    try {
        return _impl->readFromFile(handle, length);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StoreApi::seekInFile(const int64_t handle, const int64_t pos) {
    validateEndpoint();
    core::Validator::validateNumberNonNegative(pos, "field:pos ");
    try {
        return _impl->seekInFile(handle, pos);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string StoreApi::closeFile(const int64_t handle) {
    validateEndpoint();
    try {
        return _impl->closeFile(handle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

File StoreApi::getFile(const std::string& fileId) {
    core::Validator::validateId(fileId, "field:fileId ");
    try {
        return _impl->getFile(fileId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<File> StoreApi::listFiles(const std::string& storeId, const core::PagingQuery& listQuery) {
    core::Validator::validateId(storeId, "field:storeId ");
    core::Validator::validatePagingQuery(listQuery, {"createDate", "updates"}, "field:listQuery ");
    try {
        return _impl->listFiles(storeId, listQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StoreApi::subscribeForStoreEvents(const std::set<std::string>& eventTypes) {
    validateEndpoint();
    for(auto& eventType: eventTypes) {
        core::Validator::validateEnumParamString(eventType, {"create", "update", "stats", "delete"}, "eventType", "field:eventTypes:\""+eventType+"\" ");
    }
    try {
        return _impl->subscribeForStoreEvents(eventTypes);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StoreApi::unsubscribeFromStoreEvents(const std::set<std::string>& eventTypes) {
    validateEndpoint();
    for(auto& eventType: eventTypes) {
        core::Validator::validateEnumParamString(eventType, {"create", "update", "stats", "delete"}, "eventType", "field:eventTypes:\""+eventType+"\" ");
    }
    try {
        return _impl->unsubscribeFromStoreEvents(eventTypes);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StoreApi::subscribeForFileEvents(const std::string& storeId, const std::set<std::string>& eventTypes) {
    validateEndpoint();
    core::Validator::validateId(storeId, "field:storeId ");
    for(auto& eventType: eventTypes) {
        core::Validator::validateEnumParamString(eventType, {"create", "update", "stats", "delete"}, "eventType", "field:eventTypes:\""+eventType+"\" ");
    }
    try {
        return _impl->subscribeForFileEvents(storeId, eventTypes);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StoreApi::unsubscribeFromFileEvents(const std::string& storeId, const std::set<std::string>& eventTypes) {
    validateEndpoint();
    core::Validator::validateId(storeId, "field:storeId ");
    for(auto& eventType: eventTypes) {
        core::Validator::validateEnumParamString(eventType, {"create", "update", "stats", "delete"}, "eventType", "field:eventTypes:\""+eventType+"\" ");
    }
    try {
        return _impl->unsubscribeFromFileEvents(storeId, eventTypes);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StoreApi::updateFileMeta(const std::string& fileId, const core::Buffer& publicMeta, const core::Buffer& privateMeta) {
    validateEndpoint();
    core::Validator::validateId(fileId, "field:fileId ");
    try {
        return _impl->updateFileMeta(fileId, publicMeta, privateMeta);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}