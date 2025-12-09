/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/core/Validator.hpp>
#include <privmx/endpoint/store/FileDataProvider.hpp>

#include "privmx/endpoint/inbox/InboxApi.hpp"
#include "privmx/endpoint/inbox/InboxApiImpl.hpp"
#include "privmx/endpoint/inbox/InboxException.hpp"
#include "privmx/endpoint/core/EventVarSerializer.hpp"

using namespace privmx::endpoint::inbox;
using namespace privmx::endpoint;

InboxApi::InboxApi() {};
InboxApi::InboxApi(const InboxApi& obj): ExtendedPointer(obj) {};
InboxApi& InboxApi::operator=(const InboxApi& obj) {
    this->ExtendedPointer::operator=(obj);
    return *this;
};
InboxApi::InboxApi(InboxApi&& obj): ExtendedPointer(std::move(obj)) {};
InboxApi::~InboxApi() {}

InboxApi InboxApi::create(core::Connection& connection, thread::ThreadApi& threadApi, store::StoreApi& storeApi) {
    try {
        std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
        std::shared_ptr<store::RequestApi> requestApi {new store::RequestApi(connectionImpl->getGateway())};
        std::shared_ptr<ServerApi> serverApi {new ServerApi(connectionImpl->getGateway())};;
        std::shared_ptr<InboxApiImpl> impl(new InboxApiImpl(
            connection,
            threadApi,
            storeApi,
            connectionImpl->getKeyProvider(),
            serverApi,
            requestApi,
            connectionImpl->getHost(),
            connectionImpl->getUserPrivKey(),
            connectionImpl->getEventMiddleware(),
            connectionImpl->getHandleManager(),
            connectionImpl->getServerConfig().requestChunkSize
        ));
        impl->attach(impl);
        return InboxApi(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

InboxApi::InboxApi(const std::shared_ptr<InboxApiImpl>& impl) : ExtendedPointer(impl) {}

std::string InboxApi::createInbox(
const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
                            const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                            const std::optional<inbox::FilesConfig>& filesConfig,
                            const std::optional<core::ContainerPolicyWithoutItem>& policies) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return impl->createInbox(contextId, users, managers, publicMeta, privateMeta, filesConfig, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::updateInbox(
    const std::string& inboxId, const std::vector<core::UserWithPubKey>& users,
                     const std::vector<core::UserWithPubKey>& managers,
                     const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                     const std::optional<inbox::FilesConfig>& filesConfig, const int64_t version, const bool force,
                     const bool forceGenerateNewKey,
                     const std::optional<core::ContainerPolicyWithoutItem>& policies
) {
    auto impl = getImpl();
    core::Validator::validateId(inboxId, "field:inboxId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return impl->updateInbox(inboxId, users, managers, publicMeta, privateMeta, filesConfig, version, force, forceGenerateNewKey, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Inbox InboxApi::getInbox(const std::string& inboxId) {
    auto impl = getImpl();
    core::Validator::validateId(inboxId, "field:inboxId ");
    try {
        return impl->getInbox(inboxId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<inbox::Inbox> InboxApi::listInboxes(const std::string& contextId, const core::PagingQuery& query) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(query, {"createDate", "lastModificationDate"}, "field:query ");
    try {
        return impl->listInboxes(contextId, query);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

InboxPublicView InboxApi::getInboxPublicView(const std::string& inboxId) {
    auto impl = getImpl();
    core::Validator::validateId(inboxId, "field:inboxId ");
    try {
        return impl->getInboxPublicView(inboxId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::deleteInbox(const std::string& inboxId) {
    auto impl = getImpl();
    core::Validator::validateId(inboxId, "field:inboxId ");
    try {
        return impl->deleteInbox(inboxId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t/*inboxHandle*/ InboxApi::prepareEntry(
        const std::string& inboxId, 
        const core::Buffer& data,
        const std::vector<int64_t>& inboxFileHandles,
        const std::optional<std::string>& userPrivKey
    ) {
    auto impl = getImpl();
    core::Validator::validateId(inboxId, "field:inboxId ");
    if(userPrivKey.has_value()) {
        core::Validator::validatePrivKeyWIF(userPrivKey.value());
    }
    try {
        return impl->prepareEntry(inboxId, data, inboxFileHandles, userPrivKey);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::sendEntry(const int64_t inboxHandle) {
    auto impl = getImpl();
    try {
        return impl->sendEntry(inboxHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

inbox::InboxEntry InboxApi::readEntry(const std::string& inboxEntryId) {
    auto impl = getImpl();
    core::Validator::validateId(inboxEntryId, "field:inboxEntryId ");
    try {
        return impl->readEntry(inboxEntryId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::deleteEntry(const std::string& inboxEntryId) {
    auto impl = getImpl();
    core::Validator::validateId(inboxEntryId, "field:inboxEntryId ");
    try {
        return impl->deleteEntry(inboxEntryId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<inbox::InboxEntry> InboxApi::listEntries(const std::string& inboxId, const core::PagingQuery& query) {
    auto impl = getImpl();
    core::Validator::validateId(inboxId, "field:inboxId ");
    core::Validator::validatePagingQuery(query, {"createDate"}, "field:query ");
    try {
        return impl->listEntries(inboxId, query);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t/*inboxFileHandle*/ InboxApi::createFileHandle(const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t& fileSize) {
    auto impl = getImpl();
    core::Validator::validateNumberNonNegative(fileSize, "field:fileSize ");
    try {
        return impl->createFileHandle(publicMeta, privateMeta, fileSize);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
} 

void InboxApi::writeToFile(const int64_t inboxHandle, const int64_t inboxFileHandle, const core::Buffer& dataChunk) {
    auto impl = getImpl();
    try {
        return impl->writeToFile(inboxHandle, inboxFileHandle, dataChunk);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t InboxApi::openFile(const std::string& fileId) {
    auto impl = getImpl();
    core::Validator::validateId(fileId, "field:fileId ");
    try {
        return impl->openFile(fileId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::Buffer InboxApi::readFromFile(const int64_t handle, const int64_t length) {
    auto impl = getImpl();
    core::Validator::validateNumberNonNegative(length, "field:length ");
    try {
        return impl->readFromFile(handle, length);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::seekInFile(const int64_t handle, const int64_t pos) {
    auto impl = getImpl();
    core::Validator::validateNumberNonNegative(pos, "field:pos ");
    try {
        return impl->seekInFile(handle, pos);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string InboxApi::closeFile(const int64_t handle) {
    auto impl = getImpl();
    try {
        return impl->closeFile(handle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<std::string> InboxApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    try {
        return impl->subscribeFor(subscriptionQueries);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    try {
        return impl->unsubscribeFrom(subscriptionIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string InboxApi::buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    auto impl = getImpl();
    try {
        return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}