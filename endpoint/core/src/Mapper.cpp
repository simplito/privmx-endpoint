/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/Mapper.hpp"

using namespace privmx::endpoint::core;

CollectionItemChange Mapper::mapToCollectionItemChange(const server::CollectionItemChange& data) {
    return {
        .itemId = data.itemId(),
        .action = data.action()
    };
}

std::vector<CollectionItemChange> Mapper::mapToCollectionItemChanges(const privmx::utils::List<server::CollectionItemChange>& data) {
    std::vector<CollectionItemChange> result;
    result.reserve(data.size());
    for (auto item : data) {
        result.push_back(mapToCollectionItemChange(item));
    }
    return result;
}

CollectionChangedEventData Mapper::mapToCollectionChangedEventData(const std::string& moduleType, const server::CollectionChangedEventData& data) {
    return {
        .moduleType = moduleType,
        .moduleId = data.containerId(),
        .affectedItemsCount = data.affectedItemsCount(),
        .items = mapToCollectionItemChanges(data.items())

    };
}
