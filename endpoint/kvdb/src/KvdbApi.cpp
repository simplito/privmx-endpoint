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
#include <privmx/endpoint/core/Validator.hpp>

#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/kvdb/KvdbApiImpl.hpp"
#include "privmx/endpoint/kvdb/KvdbException.hpp"
#include <privmx/endpoint/group/GroupApi.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

KvdbApi KvdbApi::create(core::Connection& connection, const std::optional<group::GroupApi>& groupApi) {
    std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
    std::shared_ptr<KvdbApiImpl> impl(new KvdbApiImpl(
        connectionImpl->getGateway(), connectionImpl->getUserPrivKey(), connectionImpl->getKeyProvider(),
        connectionImpl->getHost(), connectionImpl->getEventMiddleware(), connection, groupApi
    ));
    return KvdbApi(impl);
}

KvdbApi::KvdbApi(const std::shared_ptr<KvdbApiImpl>& impl) : BaseApiClass(impl) {}

std::string KvdbApi::createKvdb(
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
    return impl->createKvdb(contextId, users, managers, publicMeta, privateMeta, policies, groups);
}

void KvdbApi::updateKvdb(
    const std::string& kvdbId,
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
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    return impl->updateKvdb(
        kvdbId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies, groups
    );
}

void KvdbApi::rotateKvdbKeys(
    const std::string& kvdbId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const int64_t version,
    const bool force,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    impl->rotateKvdbKeys(kvdbId, users, managers, version, force, groups);
}

void KvdbApi::deleteKvdb(const std::string& kvdbId) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    return impl->deleteKvdb(kvdbId);
}

Kvdb KvdbApi::getKvdb(const std::string& kvdbId) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    return impl->getKvdb(kvdbId);
}
core::PagingList<Kvdb> KvdbApi::listKvdbs(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(pagingQuery, {"createDate"}, "field:pagingQuery ");
    return impl->listKvdbs(contextId, pagingQuery);
}

KvdbEntry KvdbApi::getEntry(const std::string& kvdbId, const std::string& key) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    return impl->getEntry(kvdbId, key);
}

std::optional<KvdbEntry> KvdbApi::findEntry(const std::string& kvdbId, const std::string& key) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    return impl->findEntry(kvdbId, key);
}

bool KvdbApi::hasEntry(const std::string& kvdbId, const std::string& key) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    return impl->hasEntry(kvdbId, key);
}

core::PagingList<std::string> KvdbApi::listEntriesKeys(
    const std::string& kvdbId,
    const core::PagingQuery& pagingQuery
) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    core::Validator::validatePagingQuery(
        pagingQuery, {"createDate", "entryKey", "lastModificationDate"}, "field:pagingQuery "
    );
    return impl->listEntriesKeys(kvdbId, pagingQuery);
}
core::PagingList<KvdbEntry> KvdbApi::listEntries(const std::string& kvdbId, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    core::Validator::validatePagingQuery(
        pagingQuery, {"createDate", "entryKey", "lastModificationDate"}, "field:pagingQuery "
    );
    return impl->listEntries(kvdbId, pagingQuery);
}

void KvdbApi::setEntry(
    const std::string& kvdbId,
    const std::string& key,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    int64_t version
) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    return impl->setEntry(kvdbId, key, publicMeta, privateMeta, data, version);
}

void KvdbApi::deleteEntry(const std::string& kvdbId, const std::string& key) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    return impl->deleteEntry(kvdbId, key);
}

std::map<std::string, bool> KvdbApi::deleteEntries(const std::string& kvdbId, const std::vector<std::string>& keys) {
    auto impl = getImpl();
    core::Validator::validateId(kvdbId, "field:kvdbId ");
    return impl->deleteEntries(kvdbId, keys);
}

std::vector<std::string> KvdbApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    return impl->subscribeFor(subscriptionQueries);
}

void KvdbApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    return impl->unsubscribeFrom(subscriptionIds);
}

std::string KvdbApi::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    auto impl = getImpl();
    return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
}

std::string KvdbApi::buildSubscriptionQueryForSelectedEntry(
    EventType eventType,
    const std::string& kvdbId,
    const std::string& kvdbEntryKey
) {
    auto impl = getImpl();
    return impl->buildSubscriptionQueryForSelectedEntry(eventType, kvdbId, kvdbEntryKey);
}