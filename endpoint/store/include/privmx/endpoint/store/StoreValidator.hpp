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

template<>
class StructValidator<store::StoreStatsChangedEventData>
{
public:
    static void validate(const store::StoreStatsChangedEventData& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "StoreStatsChangedEventData";}
};

template<>
class StructValidator<store::StoreFileDeletedEventData>
{
public:
    static void validate(const store::StoreFileDeletedEventData& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "StoreFileDeletedEventData";}
};

template<>
class StructValidator<store::StoreCreatedEvent>
{
public:
    static void validate(const store::StoreCreatedEvent& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "StoreCreated";}
};

template<>
class StructValidator<store::StoreUpdatedEvent>
{
public:
    static void validate(const store::StoreUpdatedEvent& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "StoreUpdated";}
};

template<>
class StructValidator<store::StoreStatsChangedEvent>
{
public:
    static void validate(const store::StoreStatsChangedEvent& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "StoreStatsChanged";}
};

template<>
class StructValidator<store::StoreFileCreatedEvent>
{
public:
    static void validate(const store::StoreFileCreatedEvent& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "StoreFileCreated";}
};

template<>
class StructValidator<store::StoreFileUpdatedEvent>
{
public:
    static void validate(const store::StoreFileUpdatedEvent& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "StoreFileUpdated";}
};

template<>
class StructValidator<store::StoreFileDeletedEvent>
{
public:
    static void validate(const store::StoreFileDeletedEvent& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "StoreFileDeleted";}
};


} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_STOREVALIDATOR_HPP_
