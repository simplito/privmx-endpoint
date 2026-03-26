/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/sql/VarSerializer.hpp"
#include "privmx/endpoint/sql/Types.hpp"
#include "privmx/endpoint/sql/DatabaseHandle.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;


template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<sql::SqlDatabase>>(const core::PagingList<sql::SqlDatabase>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<sql$SqlDatabase>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<sql::SqlDatabase>(const sql::SqlDatabase& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "sql$SqlDatabase");
    }
    obj->set("contextId", serialize(val.contextId));
    obj->set("sqlDatabaseId", serialize(val.sqlDatabaseId));
    obj->set("createDate", serialize(val.createDate));
    obj->set("creator", serialize(val.creator));
    obj->set("lastModificationDate", serialize(val.lastModificationDate));
    obj->set("lastModifier", serialize(val.lastModifier));
    obj->set("users", serialize(val.users));
    obj->set("managers", serialize(val.managers));
    obj->set("version", serialize(val.version));
    obj->set("publicMeta", serialize(val.publicMeta));
    obj->set("privateMeta", serialize(val.privateMeta));
    obj->set("policy", serialize(val.policy));
    obj->set("statusCode", serialize(val.statusCode));
    obj->set("schemaVersion", serialize(val.schemaVersion));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<sql::DataType>(const sql::DataType& val) {
    return Poco::Dynamic::Var(static_cast<int64_t>(val));
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<sql::EvaluationStatus>(const sql::EvaluationStatus& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "sql$EvaluationStatus");
    }
    obj->set("code", serialize(static_cast<int64_t>(val.code)));
    obj->set("description", serialize(val.description));
    return obj;
}
