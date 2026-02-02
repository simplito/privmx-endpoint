/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_TYPES_HPP_

#include <cstdint>
#include <string>

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/Types.hpp"


namespace privmx {
namespace endpoint {
namespace search {

/**
 * Defines the mode in which the Search Index operates, specifically regarding 
 * the storage and retrieval of document content.
 */
enum IndexMode : int64_t
{
    /**
     * The Index stores the full document content internally. 
     * When searching, the full content field of the Document struct will be returned.
     * This mode requires more storage but simplifies content retrieval.
     */
    WITH_CONTENT,

    /**
     * The Index only stores metadata and terms necessary for search, 
     * but discards the original document content.
     * When searching, the content field of the returned Document struct will be empty.
     * This mode saves storage space, assuming content is retrieved from an external source (e.g., store::StoreApi)
     * using the Document ID and name.
     */
    WITHOUT_CONTENT
};

/**
 * Holds all available information about a Search Index.
 */
struct SearchIndex
{
    /**
     * ID of the Context
     */
    std::string contextId;

    /**
     * ID of the Search Index
     */
    std::string indexId;

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
     * list of users (their IDs) with access to the Search Index
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
     * Search Index public metadata
     */
    core::Buffer publicMeta;

    /**
     * Search Index private metadata
     */
    core::Buffer privateMeta;

    /**
     * Search Index policies
     */
    core::ContainerPolicy policy;

    /**
     * The operating mode of the Index, defining how document content is handled.
     */
    IndexMode mode;

    /**
     * status code of retrieval and decryption of the Search Index
     */
    int64_t statusCode;

    /**
     * Version of the Search Index data structure and how it is encoded/encrypted
     */
    int64_t schemaVersion;
};

/**
 * A structure representing a document for indexing.
 */
struct Document
{
    /**
     * Document ID
     */
    int64_t documentId;

    /**
     * Document name
     */
    std::string name;

    /**
     * Document content
     */
    std::string content;
};

}  // namespace search
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SEARCH_TYPES_HPP_
