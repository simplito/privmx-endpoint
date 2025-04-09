/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>

#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/kvdb/KvdbApiImpl.hpp"
#include "privmx/endpoint/kvdb/KvdbVarSerializer.hpp"
#include "privmx/endpoint/kvdb/KvdbException.hpp"
#include "privmx/endpoint/kvdb/KvdbValidator.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

KvdbApi KvdbApi::create(core::Connection& connection) {
    try {
        std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
        std::shared_ptr<KvdbApiImpl> impl(new KvdbApiImpl(
            connectionImpl->getGateway(),
            connectionImpl->getUserPrivKey(),
            connectionImpl->getKeyProvider(),
            connectionImpl->getHost(),
            connectionImpl->getEventMiddleware(),
            connectionImpl->getEventChannelManager(),
            connection
        ));
        return KvdbApi(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

KvdbApi::KvdbApi(const std::shared_ptr<KvdbApiImpl>& impl) : _impl(impl) {}

void KvdbApi::validateEndpoint() {
    if(!_impl) throw NotInitializedException();
}

std::string KvdbApi::createKvdb(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers, 
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta, 
    const std::optional<core::ContainerPolicy>& policies
) {
    validateEndpoint();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return _impl->createKvdb(contextId, users, managers, publicMeta, privateMeta, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void KvdbApi::updateKvdb(const std::string& kvdbId, 
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers, 
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta,
    const int64_t version, 
    const bool force, 
    const bool forceGenerateNewKey, 
    const std::optional<core::ContainerPolicy>& policies
)  {
    validateEndpoint();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return _impl->updateKvdb(kvdbId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void KvdbApi::deleteKvdb(const std::string& kvdbId) {
    validateEndpoint();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    try {
        return _impl->deleteKvdb(kvdbId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Kvdb KvdbApi::getKvdb(const std::string& kvdbId) {
    validateEndpoint();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    try {
        return _impl->getKvdb(kvdbId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
core::PagingList<Kvdb> KvdbApi::listKvdbs(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    validateEndpoint();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<core::PagingQuery>(pagingQuery, "field:pagingQuery ");
    try {
        return _impl->listKvdbs(contextId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Item KvdbApi::getItem(const std::string& kvdbId, const std::string& key) {
    validateEndpoint();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    try {
        return _impl->getItem(kvdbId, key);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<std::string> KvdbApi::listItemKeys(const std::string& kvdbId, const kvdb::KeysPagingQuery& pagingQuery) {
    validateEndpoint();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    core::Validator::validateClass<kvdb::KeysPagingQuery>(pagingQuery, "field:pagingQuery ");
    try {
        return _impl->listItemKeys(kvdbId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
core::PagingList<Item> KvdbApi::listItem(const std::string& kvdbId, const kvdb::ItemsPagingQuery& pagingQuery) {
    validateEndpoint();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    core::Validator::validateClass<kvdb::ItemsPagingQuery>(pagingQuery, "field:pagingQuery ");
    try {
        return _impl->listItem(kvdbId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void KvdbApi::setItem(const std::string& kvdbId, const std::string& key, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data, int64_t version) {
    validateEndpoint();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    try {
        return _impl->setItem(kvdbId, key, publicMeta, privateMeta, data, version);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void KvdbApi::deleteItem(const std::string& kvdbId, const std::string& key) {
    validateEndpoint();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    try {
        return _impl->deleteItem(kvdbId, key);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void KvdbApi::deleteItems(const std::string& kvdbId, const std::vector<std::string>& keys) {
    validateEndpoint();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    try {
        return _impl->deleteItems(kvdbId, keys);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void KvdbApi::subscribeForKvdbEvents() {
    validateEndpoint();
    try {
        return _impl->subscribeForKvdbEvents();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
void KvdbApi::unsubscribeFromKvdbEvents() {
    validateEndpoint();
    try {
        return _impl->unsubscribeFromKvdbEvents();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
void KvdbApi::subscribeForItemEvents(std::string kvdbId) {
    validateEndpoint();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    try {
        return _impl->subscribeForItemEvents(kvdbId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
void KvdbApi::unsubscribeFromItemEvents(std::string kvdbId) {
    validateEndpoint();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    try {
        return _impl->unsubscribeFromItemEvents(kvdbId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
