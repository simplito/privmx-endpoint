/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/store/StoreException.hpp>

#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/store/StoreApiImpl.hpp"
#include "privmx/endpoint/store/StoreValidator.hpp"
#include <privmx/endpoint/group/GroupApi.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

StoreApi StoreApi::create(core::Connection& connection, const std::optional<group::GroupApi>& groupApi) {
    std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
    std::shared_ptr<ServerApi> serverApi(new ServerApi(connectionImpl->getGateway()));
    std::shared_ptr<RequestApi> requestApi(new RequestApi(connectionImpl->getGateway()));
    std::shared_ptr<StoreApiImpl> impl(new StoreApiImpl(
        connectionImpl->getKeyProvider(), serverApi, connectionImpl->getHost(), connectionImpl->getUserPrivKey(),
        requestApi, std::shared_ptr<FileDataProvider>(new FileDataProvider(serverApi)),
        connectionImpl->getEventMiddleware(), connectionImpl->getHandleManager(), connection,
        connectionImpl->getServerConfig().requestChunkSize, groupApi
    ));
    return StoreApi(impl);
}

StoreApi::StoreApi(const std::shared_ptr<StoreApiImpl>& impl) : BaseApiClass(impl) {}

std::string StoreApi::createStore(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    return impl->createStore(contextId, users, managers, publicMeta, privateMeta, policies, "store", groups);
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
    const std::optional<core::ContainerPolicy>& policies,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(storeId, "field:storeId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    impl->updateStore(
        storeId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies, groups
    );
}

void StoreApi::rotateStoreKeys(
    const std::string& storeId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const int64_t version,
    const bool force,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(storeId, "field:storeId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    impl->rotateStoreKeys(storeId, users, managers, version, force, groups);
}

void StoreApi::deleteStore(const std::string& storeId) {
    auto impl = getImpl();
    core::Validator::validateId(storeId, "field:storeId ");
    return impl->deleteStore(storeId);
}

Store StoreApi::getStore(const std::string& storeId) {
    auto impl = getImpl();
    core::Validator::validateId(storeId, "field:storeId ");
    return impl->getStore(storeId);
}

core::PagingList<Store> StoreApi::listStores(const std::string& contextId, const core::PagingQuery& query) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(query, {"createDate", "lastModificationDate", "lastFileDate"}, "field:query ");
    return impl->listStores(contextId, query);
}

void StoreApi::deleteFile(const std::string& fileId) {
    auto impl = getImpl();
    core::Validator::validateId(fileId, "field:fileId ");
    impl->deleteFile(fileId);
}

int64_t StoreApi::createFile(
    const std::string& storeId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t size,
    bool randomWriteSupport
) {
    auto impl = getImpl();
    core::Validator::validateId(storeId, "field:storeId ");
    core::Validator::validateNumberNonNegative(size, "field:size ");
    return impl->createFile(storeId, publicMeta, privateMeta, size, randomWriteSupport);
}

int64_t StoreApi::updateFile(
    const std::string& fileId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t size
) {
    auto impl = getImpl();
    core::Validator::validateId(fileId, "field:fileId ");
    core::Validator::validateNumberNonNegative(size, "field:size ");
    return impl->updateFile(fileId, publicMeta, privateMeta, size);
}

int64_t StoreApi::openFile(const std::string& fileId) {
    auto impl = getImpl();
    core::Validator::validateId(fileId, "field:fileId ");
    return impl->openFile(fileId);
}

void StoreApi::writeToFile(const int64_t handle, const core::Buffer& dataChunk, bool truncate) {
    auto impl = getImpl();
    return impl->writeToFile(handle, dataChunk, truncate);
}

core::Buffer StoreApi::readFromFile(const int64_t handle, const int64_t length) {
    auto impl = getImpl();
    core::Validator::validateNumberNonNegative(length, "field:length ");
    return impl->readFromFile(handle, length);
}

void StoreApi::seekInFile(const int64_t handle, const int64_t pos) {
    auto impl = getImpl();
    core::Validator::validateNumberNonNegative(pos, "field:pos ");
    return impl->seekInFile(handle, pos);
}

std::string StoreApi::closeFile(const int64_t handle) {
    auto impl = getImpl();
    return impl->closeFile(handle);
}

File StoreApi::getFile(const std::string& fileId) {
    auto impl = getImpl();
    core::Validator::validateId(fileId, "field:fileId ");
    return impl->getFile(fileId);
}

core::PagingList<File> StoreApi::listFiles(const std::string& storeId, const core::PagingQuery& listQuery) {
    auto impl = getImpl();
    core::Validator::validateId(storeId, "field:storeId ");
    core::Validator::validatePagingQuery(listQuery, {"createDate", "updates"}, "field:listQuery ");
    return impl->listFiles(storeId, listQuery);
}

void StoreApi::updateFileMeta(
    const std::string& fileId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta
) {
    auto impl = getImpl();
    core::Validator::validateId(fileId, "field:fileId ");
    return impl->updateFileMeta(fileId, publicMeta, privateMeta);
}

void StoreApi::syncFile(const int64_t handle) {
    auto impl = getImpl();
    return impl->syncFile(handle);
}

void StoreApi::flushFile(const int64_t handle) {
    auto impl = getImpl();
    return impl->flushFile(handle);
}

uint64_t StoreApi::getFileSize(const int64_t handle) {
    auto impl = getImpl();
    return impl->getFileSize(handle);
}

std::vector<std::string> StoreApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    return impl->subscribeFor(subscriptionQueries);
}

void StoreApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    return impl->unsubscribeFrom(subscriptionIds);
}

std::string StoreApi::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    auto impl = getImpl();
    return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
}
