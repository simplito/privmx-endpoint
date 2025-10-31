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


namespace privmx {
namespace endpoint {
namespace search {

enum IndexMode
{
    WITH_CONTENT,
    WITHOUT_CONTENT
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
