/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_KVDBVALIDATOR_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_KVDBVALIDATOR_HPP_

#include <string>
#include <privmx/endpoint/core/Validator.hpp>
#include "privmx/endpoint/kvdb/Types.hpp"
#include "privmx/endpoint/kvdb/Events.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
class StructValidator<kvdb::KvdbEntryPagingQuery>
{
public:
    static void validate(const kvdb::KvdbEntryPagingQuery& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "KvdbEntryPagingQuery";}
};

template<>
class StructValidator<kvdb::KvdbKeysPagingQuery>
{
public:
    static void validate(const kvdb::KvdbKeysPagingQuery& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "KvdbKeysPagingQuery";}
};

} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_KVDBVALIDATOR_HPP_
