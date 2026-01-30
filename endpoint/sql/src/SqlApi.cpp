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

#include "privmx/endpoint/sql/SqlApi.hpp"
#include "privmx/endpoint/sql/SqlApiImpl.hpp"
#include "privmx/endpoint/sql/SqlException.hpp"
#include "privmx/endpoint/core/Validator.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::sql;

SqlApi::SqlApi() {};
SqlApi::SqlApi(const SqlApi& obj): ExtendedPointer(obj) {};
SqlApi& SqlApi::operator=(const SqlApi& obj) {
    this->ExtendedPointer::operator=(obj);
    return *this;
};
SqlApi::SqlApi(SqlApi&& obj): ExtendedPointer(std::move(obj)) {};
SqlApi::~SqlApi() {}

SqlApi SqlApi::create(core::Connection& connection, store::StoreApi& storeApi, kvdb::KvdbApi& kvdbApi) {
    try {
        std::shared_ptr<SqlApiImpl> impl = std::make_shared<SqlApiImpl>(
            connection,
            storeApi,
            kvdbApi
        );
        impl->attach(impl);
        return SqlApi(impl);
    }  catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

SqlApi::SqlApi(const std::shared_ptr<SqlApiImpl>& impl) : ExtendedPointer(impl) {}


std::string SqlApi::createSqlDatabase(
    const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta,
    const core::Buffer& privateMeta, const std::optional<core::ContainerPolicy>& policies
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return impl->createSqlDatabase(contextId, users, managers, publicMeta, privateMeta, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void SqlApi::updateSqlDatabase(
    const std::string& sqlDatabaseId, const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
    const int64_t version, const bool force, const bool forceGenerateNewKey, const std::optional<core::ContainerPolicy>& policies
) {
    auto impl = getImpl();
    core::Validator::validateId(sqlDatabaseId, "field:indexId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        impl->updateSqlDatabase(sqlDatabaseId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    } 
}

void SqlApi::deleteSqlDatabase(const std::string& sqlDatabaseId) {
    auto impl = getImpl();
    core::Validator::validateId(sqlDatabaseId, "field:indexId ");
    try {
        return impl->deleteSqlDatabase(sqlDatabaseId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

SqlDatabase SqlApi::getSqlDatabase(const std::string& sqlDatabaseId) {
    auto impl = getImpl();
    core::Validator::validateId(sqlDatabaseId, "field:indexId ");
    try {
        return impl->getSqlDatabase(sqlDatabaseId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<SqlDatabase> SqlApi::listSqlDatabases(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    try {
        return impl->listSqlDatabases(contextId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::shared_ptr<DatabaseHandle> SqlApi::openSqlDatabase(const std::string& sqlDatabaseId) {
    auto impl = getImpl();
    core::Validator::validateId(sqlDatabaseId, "field:indexId ");
    try {
        return impl->openSqlDatabase(sqlDatabaseId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
