#ifndef _PRIVMXLIB_ENDPOINT_STORE_STOREVARSERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STOREVARSERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <privmx/endpoint/core/VarSerializer.hpp>
#include <string>

#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/store/StoreValidator.hpp"
#include "privmx/endpoint/store/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::Store>(const store::Store& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<store::Store>>(const core::PagingList<store::Store>& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreDeletedEventData>(const store::StoreDeletedEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreStatsChangedEventData>(
    const store::StoreStatsChangedEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreFileDeletedEventData>(
    const store::StoreFileDeletedEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreCreatedEvent>(const store::StoreCreatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreUpdatedEvent>(const store::StoreUpdatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreDeletedEvent>(const store::StoreDeletedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreStatsChangedEvent>(const store::StoreStatsChangedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreFileCreatedEvent>(const store::StoreFileCreatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreFileUpdatedEvent>(const store::StoreFileUpdatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreFileDeletedEvent>(const store::StoreFileDeletedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::File>(const store::File& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<PagingList<store::File>>(const PagingList<store::File>& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::ServerFileInfo>(const store::ServerFileInfo& val);

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STORE_STOREVARSERIALIZER_HPP_
