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
#include "privmx/endpoint/inbox/InboxVarSerializer.hpp"
#include "privmx/endpoint/inbox/InboxException.hpp"
#include "privmx/endpoint/core/EventVarSerializer.hpp"

using namespace privmx::endpoint::inbox;
using namespace privmx::endpoint;

InboxApi InboxApi::create(core::Connection& connection, thread::ThreadApi& threadApi, store::StoreApi& storeApi) {

    std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
    std::shared_ptr<store::RequestApi> requestApi {new store::RequestApi(connectionImpl->getGateway())};
    std::shared_ptr<ServerApi> serverApi {new ServerApi(connectionImpl->getGateway())};;
    std::shared_ptr<InboxApiImpl> impl(new InboxApiImpl(
        threadApi,
        storeApi,
        connectionImpl->getKeyProvider(),
        serverApi,
        requestApi,
        connectionImpl->getHost(),
        connectionImpl->getUserPrivKey(),
        connectionImpl->getEventMiddleware(),
        connectionImpl->getEventChannelManager(),
        connectionImpl->getHandleManager(),
        connectionImpl->getServerConfig().requestChunkSize
    ));
    try {
        return InboxApi(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

InboxApi::InboxApi(const std::shared_ptr<InboxApiImpl>& impl) : _impl(impl) {}

void InboxApi::validateEndpoint() {
    if(!_impl) throw NotInitializedException();
}

std::string InboxApi::createInbox(
const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
                            const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                            const std::optional<inbox::FilesConfig>& filesConfig,
                            const std::optional<core::ContainerPolicyWithoutItem>& policies) {
    validateEndpoint();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return _impl->createInbox(contextId, users, managers, publicMeta, privateMeta, filesConfig, policies);
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
    validateEndpoint();
    core::Validator::validateId(inboxId, "field:inboxId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return _impl->updateInbox(inboxId, users, managers, publicMeta, privateMeta, filesConfig, version, force, forceGenerateNewKey, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Inbox InboxApi::getInbox(const std::string& inboxId) {
    validateEndpoint();
    core::Validator::validateId(inboxId, "field:inboxId ");
    try {
        return _impl->getInbox(inboxId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<inbox::Inbox> InboxApi::listInboxes(const std::string& contextId, const core::PagingQuery& query) {
    validateEndpoint();
    core::Validator::validateId(contextId, "field:contextId ");
    core::StructValidator<core::PagingQuery>::validate(query, "field:query ");
    try {
        return _impl->listInboxes(contextId, query);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

InboxPublicView InboxApi::getInboxPublicView(const std::string& inboxId) {
    validateEndpoint();
    core::Validator::validateId(inboxId, "field:inboxId ");
    try {
        return _impl->getInboxPublicView(inboxId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::deleteInbox(const std::string& inboxId) {
    validateEndpoint();
    core::Validator::validateId(inboxId, "field:inboxId ");
    try {
        return _impl->deleteInbox(inboxId);
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
    validateEndpoint();
    core::Validator::validateId(inboxId, "field:inboxId ");
    if(userPrivKey.has_value()) {
        core::Validator::validatePrivKeyWIF(userPrivKey.value());
    }
    try {
        return _impl->prepareEntry(inboxId, data, inboxFileHandles, userPrivKey);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::sendEntry(const int64_t inboxHandle) {
    validateEndpoint();
    try {
        return _impl->sendEntry(inboxHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

inbox::InboxEntry InboxApi::readEntry(const std::string& inboxEntryId) {
    validateEndpoint();
    core::Validator::validateId(inboxEntryId, "field:inboxEntryId ");
    try {
        return _impl->readEntry(inboxEntryId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::deleteEntry(const std::string& inboxEntryId) {
    validateEndpoint();
    core::Validator::validateId(inboxEntryId, "field:inboxEntryId ");
    try {
        return _impl->deleteEntry(inboxEntryId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<inbox::InboxEntry> InboxApi::listEntries(const std::string& inboxId, const core::PagingQuery& query) {
    validateEndpoint();
    core::Validator::validateId(inboxId, "field:inboxId ");
    core::StructValidator<core::PagingQuery>::validate(query, "field:query ");
    try {
        return _impl->listEntries(inboxId, query);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t/*inboxFileHandle*/ InboxApi::createFileHandle(const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t& fileSize) {
    validateEndpoint();
    core::Validator::validateNumberNonNegative(fileSize, "field:fileSize ");
    try {
        return _impl->createFileHandle(publicMeta, privateMeta, fileSize);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
} 

void InboxApi::writeToFile(const int64_t inboxHandle, const int64_t inboxFileHandle, const core::Buffer& dataChunk) {
    validateEndpoint();
    try {
        return _impl->writeToFile(inboxHandle, inboxFileHandle, dataChunk);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t InboxApi::openFile(const std::string& fileId) {
    validateEndpoint();
    core::Validator::validateId(fileId, "field:fileId ");
    try {
        return _impl->openFile(fileId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::Buffer InboxApi::readFromFile(const int64_t handle, const int64_t length) {
    validateEndpoint();
    core::Validator::validateNumberNonNegative(length, "field:length ");
    try {
        return _impl->readFromFile(handle, length);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::seekInFile(const int64_t handle, const int64_t pos) {
    validateEndpoint();
    core::Validator::validateNumberNonNegative(pos, "field:pos ");
    try {
        return _impl->seekInFile(handle, pos);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string InboxApi::closeFile(const int64_t handle) {
    validateEndpoint();
    try {
        return _impl->closeFile(handle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::subscribeForInboxEvents() {
    validateEndpoint();
    try {
        return _impl->subscribeForInboxEvents();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::unsubscribeFromInboxEvents() {
    validateEndpoint();
    try {
        return _impl->unsubscribeFromInboxEvents();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::subscribeForEntryEvents(const std::string& inboxId) {
    validateEndpoint();
    core::Validator::validateId(inboxId, "field:inboxId ");
    try {
        return _impl->subscribeForEntryEvents(inboxId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::unsubscribeFromEntryEvents(const std::string& inboxId) {
    validateEndpoint();
    core::Validator::validateId(inboxId, "field:inboxId ");
    try {
        return _impl->unsubscribeFromEntryEvents(inboxId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::emitEvent(const std::string& inboxId, const std::string& channelName, const core::Buffer& eventData, const std::vector<std::string>& usersIds) {
    validateEndpoint();
    core::Validator::validateId(inboxId, "field:inboxId ");
    try {
        return _impl->emitEvent(inboxId, channelName, eventData, usersIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::subscribeForInboxCustomEvents(const std::string& inboxId, const std::string& channelName) {
    validateEndpoint();
    core::Validator::validateId(inboxId, "field:inboxId ");
    try {
        return _impl->subscribeForInboxCustomEvents(inboxId, channelName);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void InboxApi::unsubscribeFromInboxCustomEvents(const std::string& inboxId, const std::string& channelName) {
    validateEndpoint();
    core::Validator::validateId(inboxId, "field:inboxId ");
    try {
        return _impl->unsubscribeFromInboxCustomEvents(inboxId, channelName);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}