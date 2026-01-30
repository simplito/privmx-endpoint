/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_SQL_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_SQL_TYPES_HPP_

#include <cstdint>
#include <string>

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/Types.hpp"


namespace privmx {
namespace endpoint {
namespace sql {

struct SqlDatabase
{
    /**
     * ID of the Context
     */
    std::string contextId;

    /**
     * ID of the SQL Database
     */
    std::string sqlDatabaseId;

    /**
     * Index creation timestamp
     */
    int64_t createDate;

    /**
     * ID of user who created the Index
     */
    std::string creator;

    /**
     * Index last modification timestamp
     */
    int64_t lastModificationDate;

    /**
     * ID of the user who last modified the Index
     */
    std::string lastModifier;

    /**
     * list of users (their IDs) with access to the SQL Database
     */
    std::vector<std::string> users;

    /**
     * list of users (their IDs) with management rights
     */
    std::vector<std::string> managers;

    /**
     * Version number (changes on updates)
     */
    int64_t version;

    /**
     * SQL Database public metadata
     */
    core::Buffer publicMeta;

    /**
     * SQL Database private metadata
     */
    core::Buffer privateMeta;

    /**
     * SQL Database policies
     */
    core::ContainerPolicy policy;

    /**
     * status code of retrieval and decryption of the SQL Database
     */
    int64_t statusCode;

    /**
     * Version of the SQL Database data structure and how it is encoded/encrypted
     */
    int64_t schemaVersion;
};

}  // namespace sql
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SQL_TYPES_HPP_
