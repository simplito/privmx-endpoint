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
#include <privmx/endpoint/core/Validator.hpp>

#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/kvdb/KvdbApiImpl.hpp"
#include "privmx/endpoint/kvdb/KvdbException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

KvdbApi::KvdbApi() {};
KvdbApi::KvdbApi(const KvdbApi& obj): _impl(obj._impl) {
    attachToImplIfPossible();
};
KvdbApi& KvdbApi::operator=(const KvdbApi& obj) {
    _impl = obj._impl;
    attachToImplIfPossible();
    return *this;
};
KvdbApi::KvdbApi(KvdbApi&& obj): _impl(obj._impl) {
    attachToImplIfPossible();
};
KvdbApi::~KvdbApi() {
    detachFromImplIfPossible();
}

KvdbApi KvdbApi::create(core::Connection& connection) {
    try {
        std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
        std::shared_ptr<KvdbApiImpl> impl(new KvdbApiImpl(
            connectionImpl->getGateway(),
            connectionImpl->getUserPrivKey(),
            connectionImpl->getKeyProvider(),
            connectionImpl->getHost(),
            connectionImpl->getEventMiddleware(),
            connection
        ));
        impl->attach(impl);
        return KvdbApi(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

KvdbApi::KvdbApi(const std::shared_ptr<KvdbApiImpl>& impl) : _impl(impl) {}

std::shared_ptr<KvdbApiImpl> KvdbApi::getImpl() const { 
    auto impl = _impl.lock();
    if(!impl) throw NotInitializedException();
    return impl; 
}

void KvdbApi::attachToImplIfPossible() {
    if(!_impl.expired()) {
        auto impl = _impl.lock();
        if(impl) {
            impl->attach();
        }
    }
};

void KvdbApi::detachFromImplIfPossible() {
    if(!_impl.expired()) {
        auto impl = _impl.lock();
        if(impl) {
            impl->detach();
        }
    }
}

std::string KvdbApi::createKvdb(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers, 
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta, 
    const std::optional<core::ContainerPolicy>& policies
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return impl->createKvdb(contextId, users, managers, publicMeta, privateMeta, policies);
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
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return impl->updateKvdb(kvdbId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void KvdbApi::deleteKvdb(const std::string& kvdbId) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    try {
        return impl->deleteKvdb(kvdbId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Kvdb KvdbApi::getKvdb(const std::string& kvdbId) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    try {
        return impl->getKvdb(kvdbId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
core::PagingList<Kvdb> KvdbApi::listKvdbs(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(pagingQuery, {"createDate"}, "field:pagingQuery ");
    try {
        return impl->listKvdbs(contextId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

KvdbEntry KvdbApi::getEntry(const std::string& kvdbId, const std::string& key) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    try {
        return impl->getEntry(kvdbId, key);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool KvdbApi::hasEntry(const std::string& kvdbId, const std::string& key) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    try {
        return impl->hasEntry(kvdbId, key);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<std::string> KvdbApi::listEntriesKeys(const std::string& kvdbId, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    core::Validator::validatePagingQuery(pagingQuery, {"createDate", "entryKey", "lastModificationDate"}, "field:pagingQuery ");
    try {
        return impl->listEntriesKeys(kvdbId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
core::PagingList<KvdbEntry> KvdbApi::listEntries(const std::string& kvdbId, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    core::Validator::validatePagingQuery(pagingQuery, {"createDate", "entryKey", "lastModificationDate"}, "field:pagingQuery ");
    try {
        return impl->listEntries(kvdbId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void KvdbApi::setEntry(const std::string& kvdbId, const std::string& key, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data, int64_t version) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    try {
        return impl->setEntry(kvdbId, key, publicMeta, privateMeta, data, version);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void KvdbApi::deleteEntry(const std::string& kvdbId, const std::string& key) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    try {
        return impl->deleteEntry(kvdbId, key);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::map<std::string, bool> KvdbApi::deleteEntries(const std::string& kvdbId, const std::vector<std::string>& keys) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    try {
        return impl->deleteEntries(kvdbId, keys);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<std::string> KvdbApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    try {
        return impl->subscribeFor(subscriptionQueries);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void KvdbApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    try {
        return impl->unsubscribeFrom(subscriptionIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string KvdbApi::buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    auto impl = getImpl();
    try {
        return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string KvdbApi::buildSubscriptionQueryForSelectedEntry(EventType eventType, const std::string& kvdbId, const std::string& kvdbEntryKey) {
    auto impl = getImpl();
    try {
        return impl->buildSubscriptionQueryForSelectedEntry(eventType, kvdbId, kvdbEntryKey);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}