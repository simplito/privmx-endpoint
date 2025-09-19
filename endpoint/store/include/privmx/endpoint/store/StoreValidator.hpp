/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_STOREVALIDATOR_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STOREVALIDATOR_HPP_

#include <string>
#include <privmx/endpoint/core/Validator.hpp>
#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/store/Events.hpp"


namespace privmx {
namespace endpoint {
namespace core {

template<>
class StructValidator<store::Store>
{
public:
    static void validate(const store::Store& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "Store";}
};

template<>
class StructValidator<PagingList<store::Store>>
{
public:
    static void validate(const PagingList<store::Store>& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "PagingList<Store>";}
};

template<>
class StructValidator<store::File>
{
public:
    static void validate(const store::File& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "File";}
};

template<>
class StructValidator<PagingList<store::File>>
{
public:
    static void validate(const PagingList<store::File>& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "PagingList<File>";}
};



} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_STOREVALIDATOR_HPP_
