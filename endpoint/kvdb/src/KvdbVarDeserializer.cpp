/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/KvdbVarDeserializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include "privmx/endpoint/core/TypeValidator.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;


template<>
kvdb::PagingQuery core::VarDeserializer::deserialize<kvdb::PagingQuery>(const Poco::Dynamic::Var& val, const std::string& name) {
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {.skip = deserialize<int64_t>(obj->get("skip"), name + ".skip"),
            .limit = deserialize<int64_t>(obj->get("limit"), name + ".limit"),
            .sortOrder = deserialize<std::string>(obj->get("sortOrder"), name + ".sortOrder"),
            .sortBy = deserializeOptional<std::string>(obj->get("sortBy"), name + ".sortBy"),
            .lastKey = deserializeOptional<std::string>(obj->get("lastKey"), name + ".lastKey"),
            .prefix = deserializeOptional<std::string>(obj->get("prefix"), name + ".prefix"),
            .queryAsJson = deserializeOptional<std::string>(obj->get("queryAsJson"), name + ".queryAsJson")
        };
}

